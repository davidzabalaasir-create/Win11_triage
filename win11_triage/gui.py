"""Interfaz gráfica de escritorio (CustomTkinter).

Arranque: ``win11-triage-gui``, ``win11-triage --gui`` o ``python -m win11_triage.gui``.
El análisis corre en un hilo aparte; la interfaz solo se actualiza desde el hilo
principal a través de una cola de eventos.
"""

from __future__ import annotations

import argparse
import logging
import os
import queue
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any

import customtkinter as ctk
from dotenv import load_dotenv, set_key

from . import __version__, env_check, report
from .engine import PLACEHOLDER_KEY, Reporter, TriageEngine, TriageOptions, default_config_dir
from .models import Cancelled, Finding, Status
from .report import TriageResult
from .utils import expand_win_vars
from .virustotal import GUI_URL
from .whitelist import Whitelist, WhitelistError, add_to_whitelist

log = logging.getLogger(__name__)

# Paleta (tema oscuro)
BG = "#0f172a"
PANEL = "#111827"
CARD = "#1f2937"
BORDER = "#374151"
TEXT = "#e5e7eb"
MUTED = "#9ca3af"
ACCENT = "#2563eb"
ACCENT_HOVER = "#1d4ed8"
STATUS_COLOR = {Status.DETECTED: "#ef4444", Status.UNKNOWN: "#eab308", Status.CLEAN: "#22c55e"}
FILTERS = {"Todos": None, "Detectados": Status.DETECTED, "Desconocidos": Status.UNKNOWN, "Limpios": Status.CLEAN}
FORMATS = {"Markdown": "md", "JSON": "json", "Markdown + JSON": "both", "No guardar": None}
SOURCE_LABEL = {"autoruns": "Persistencia", "sigcheck": "Carpeta usuario"}


# ----------------------------------------------------------------- utilidades
def open_path(path: Path | str) -> None:
    """Abre un archivo o carpeta con la aplicación predeterminada del sistema."""
    if sys.platform == "win32":
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


class QueueReporter(Reporter):
    """Traduce los eventos del motor a mensajes en una cola (thread-safe)."""

    def __init__(self, events: queue.Queue[tuple[Any, ...]]) -> None:
        self.q = events

    def stage(self, text: str) -> None:
        self.q.put(("stage", text))

    def done(self) -> None:
        self.q.put(("done",))

    def info(self, text: str) -> None:
        self.q.put(("log", "INFO", text))

    def warn(self, text: str) -> None:
        self.q.put(("log", "AVISO", text))

    def error(self, text: str) -> None:
        self.q.put(("log", "ERROR", text))

    def vt_start(self, total: int, cached: int, new: int, eta: float) -> None:
        self.q.put(("vt_start", total, cached, new, eta))

    def vt_progress(self, index: int, total: int, sha256: str, result: dict, origin: str) -> None:
        self.q.put(("vt_progress", index, total, sha256, result, origin))

    def vt_wait(self, remaining: float) -> None:
        self.q.put(("vt_wait", remaining))


class SecretDialog(ctk.CTkToplevel):
    """Diálogo modal para introducir la API key sin mostrarla en claro."""

    def __init__(self, master: ctk.CTk, current: str) -> None:
        super().__init__(master)
        self.title("Clave de VirusTotal")
        self.geometry("460x220")
        self.resizable(False, False)
        self.transient(master)
        self.value: str | None = None

        ctk.CTkLabel(self, text="API key de VirusTotal", font=ctk.CTkFont(size=15, weight="bold")).pack(
            anchor="w", padx=20, pady=(18, 2)
        )
        ctk.CTkLabel(
            self,
            text="Se guarda en el archivo .env de la carpeta de configuración.\n"
            "Consíguela gratis en virustotal.com → tu perfil → API key.",
            text_color=MUTED,
            justify="left",
        ).pack(anchor="w", padx=20)
        self.entry = ctk.CTkEntry(self, show="•", width=420)
        self.entry.pack(padx=20, pady=12)
        if current and current != PLACEHOLDER_KEY:
            self.entry.insert(0, current)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=20)
        ctk.CTkButton(row, text="Guardar", width=110, command=self._ok).pack(side="right")
        ctk.CTkButton(row, text="Cancelar", width=110, fg_color=CARD, hover_color=BORDER, command=self.destroy).pack(
            side="right", padx=8
        )
        self.link = ctk.CTkButton(
            row,
            text="Obtener clave",
            width=110,
            fg_color="transparent",
            text_color=ACCENT,
            hover_color=CARD,
            command=lambda: webbrowser.open("https://www.virustotal.com/gui/my-apikey"),
        )
        self.link.pack(side="left")
        self.entry.bind("<Return>", lambda _e: self._ok())
        self.after(50, self._grab)

    def _grab(self) -> None:
        self.grab_set()
        self.entry.focus_set()

    def _ok(self) -> None:
        self.value = self.entry.get().strip()
        self.destroy()


# ----------------------------------------------------------------- aplicación
class TriageApp(ctk.CTk):
    def __init__(self, config_dir: Path) -> None:
        super().__init__()
        self.config_dir = config_dir
        self.env_file = config_dir / ".env"
        load_dotenv(self.env_file, override=True)

        self.events: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self.cancel = threading.Event()
        self.worker: threading.Thread | None = None
        self.result: TriageResult | None = None
        self.findings: list[Finding] = []
        self.reports: list[Path] = []
        self.sort_key = ("estado", False)
        self.tools = env_check.check_all()
        self.windows = env_check.is_windows()
        self.admin = env_check.is_admin()

        self.title(f"win11-triage {__version__}")
        self.geometry("1360x860")
        self.minsize(1100, 700)
        self.configure(fg_color=BG)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._style_treeview()
        self._build_sidebar()
        self._build_main()
        self._refresh_tools()
        self._update_cards()
        self._set_running(False)
        self._log("INFO", f"Carpeta de configuración: {self.config_dir}")
        if not self.windows:
            self._log("AVISO", "Este sistema no es Windows: solo está disponible el modo demostración.")

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_events)

    # ============================================================ construcción
    def _style_treeview(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Triage.Treeview",
            background=CARD,
            fieldbackground=CARD,
            foreground=TEXT,
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.map("Triage.Treeview", background=[("selected", "#1e3a8a")], foreground=[("selected", "#ffffff")])
        style.configure(
            "Triage.Treeview.Heading",
            background=PANEL,
            foreground=MUTED,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padding=(8, 6),
        )
        style.map("Triage.Treeview.Heading", background=[("active", BORDER)])
        style.layout("Triage.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    def _section(self, parent: ctk.CTkBaseClass, text: str) -> None:
        ctk.CTkLabel(parent, text=text.upper(), text_color=MUTED, font=ctk.CTkFont(size=11, weight="bold")).pack(
            anchor="w", padx=18, pady=(18, 6)
        )

    def _build_sidebar(self) -> None:
        side = ctk.CTkScrollableFrame(self, width=280, corner_radius=0, fg_color=PANEL)
        side.grid(row=0, column=0, sticky="nsw")

        ctk.CTkLabel(side, text="win11-triage", font=ctk.CTkFont(size=22, weight="bold")).pack(
            anchor="w", padx=18, pady=(20, 0)
        )
        ctk.CTkLabel(side, text=f"Triaje defensivo · v{__version__}", text_color=MUTED).pack(anchor="w", padx=18)

        if self.windows:
            badge_text, badge_color = (
                ("● Administrador", STATUS_COLOR[Status.CLEAN])
                if self.admin
                else ("● Sin privilegios de administrador", STATUS_COLOR[Status.UNKNOWN])
            )
            ctk.CTkLabel(side, text=badge_text, text_color=badge_color).pack(anchor="w", padx=18, pady=(10, 0))
            if not self.admin:
                ctk.CTkButton(
                    side,
                    text="Reiniciar como administrador",
                    fg_color=CARD,
                    hover_color=BORDER,
                    command=self._relaunch_admin,
                ).pack(fill="x", padx=18, pady=(6, 0))

        # --- Módulos
        self._section(side, "Módulos")
        self.var_autoruns = ctk.BooleanVar(value=True)
        self.var_scan_user = ctk.BooleanVar(value=True)
        self.var_network = ctk.BooleanVar(value=True)
        self.var_vt = ctk.BooleanVar(value=True)
        modules = (
            (self.var_autoruns, "Persistencia", "Programas que arrancan solos (autorunsc)"),
            (self.var_scan_user, "Carpetas de usuario", "Ejecutables sin firma en Temp y AppData"),
            (self.var_network, "Conexiones de red", "Quién de la lista está conectado (tcpvcon)"),
            (self.var_vt, "VirusTotal", "Reputación de cada hash (15 s por consulta)"),
        )
        for var, title, desc in modules:
            ctk.CTkCheckBox(side, text=title, variable=var, font=ctk.CTkFont(weight="bold")).pack(
                anchor="w", padx=18, pady=(6, 0)
            )
            ctk.CTkLabel(
                side,
                text=desc,
                text_color=MUTED,
                font=ctk.CTkFont(size=11),
                anchor="w",
                justify="left",
                wraplength=200,
            ).pack(anchor="w", fill="x", padx=(46, 12))

        # --- Opciones
        self._section(side, "Opciones")
        self.var_dry = ctk.BooleanVar(value=not self.windows)
        self.dry_switch = ctk.CTkSwitch(side, text="Modo demostración", variable=self.var_dry)
        self.dry_switch.pack(anchor="w", padx=18)
        if not self.windows:
            self.dry_switch.configure(state="disabled")
        ctk.CTkLabel(
            side, text="Usa datos de ejemplo, sin red ni herramientas", text_color=MUTED, font=ctk.CTkFont(size=11)
        ).pack(anchor="w", padx=18)

        ctk.CTkLabel(side, text="Límite de consultas nuevas a VirusTotal").pack(anchor="w", padx=18, pady=(10, 2))
        self.vt_limit = ctk.CTkEntry(side, placeholder_text="Sin límite")
        self.vt_limit.pack(fill="x", padx=18)

        ctk.CTkLabel(side, text="Guardar informe como").pack(anchor="w", padx=18, pady=(10, 2))
        self.format_menu = ctk.CTkOptionMenu(side, values=list(FORMATS))
        self.format_menu.pack(fill="x", padx=18)

        # --- Acciones
        self.run_btn = ctk.CTkButton(
            side,
            text="▶  Analizar",
            height=42,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            command=self._start,
        )
        self.run_btn.pack(fill="x", padx=18, pady=(22, 6))
        self.cancel_btn = ctk.CTkButton(
            side, text="■  Cancelar", height=34, fg_color=CARD, hover_color=BORDER, command=self._cancel
        )
        self.cancel_btn.pack(fill="x", padx=18)

        # --- Herramientas
        self._section(side, "Herramientas Sysinternals")
        self.tools_frame = ctk.CTkFrame(side, fg_color="transparent")
        self.tools_frame.pack(fill="x", padx=18)
        ctk.CTkButton(
            side, text="Volver a comprobar", height=28, fg_color=CARD, hover_color=BORDER, command=self._refresh_tools
        ).pack(fill="x", padx=18, pady=(6, 0))

        # --- Configuración
        self._section(side, "Configuración")
        for text, cmd in (
            ("Clave de VirusTotal…", self._edit_api_key),
            ("Editar lista blanca", self._open_whitelist),
            ("Carpeta de informes", self._open_reports_dir),
        ):
            ctk.CTkButton(side, text=text, height=30, fg_color=CARD, hover_color=BORDER, anchor="w", command=cmd).pack(
                fill="x", padx=18, pady=3
            )
        ctk.CTkLabel(side, text="").pack(pady=6)

    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew", padx=22, pady=18)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)

        # --- Cabecera
        head = ctk.CTkFrame(main, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(head, text="Resultados", font=ctk.CTkFont(size=24, weight="bold")).pack(side="left")
        self.subtitle = ctk.CTkLabel(head, text="Elige los módulos y pulsa Analizar.", text_color=MUTED)
        self.subtitle.pack(side="left", padx=14, pady=(6, 0))
        self.open_report_btn = ctk.CTkButton(
            head, text="Abrir informe", width=130, fg_color=CARD, hover_color=BORDER, command=self._open_report
        )
        self.open_report_btn.pack(side="right")

        # --- Tarjetas de resumen
        cards = ctk.CTkFrame(main, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", pady=(14, 10))
        self.card_values: dict[str, ctk.CTkLabel] = {}
        specs = (
            ("detected", "Detectados", "Marcados por antivirus en VT", STATUS_COLOR[Status.DETECTED]),
            ("unknown", "Sin firma / desconocidos", "Revisar manualmente", STATUS_COLOR[Status.UNKNOWN]),
            ("clean", "Limpios", "0 detecciones o firma válida", STATUS_COLOR[Status.CLEAN]),
            ("whitelist", "En lista blanca", "Ignorados por ti", MUTED),
        )
        for i, (key, title, hint, color) in enumerate(specs):
            cards.grid_columnconfigure(i, weight=1, uniform="cards")
            card = ctk.CTkFrame(cards, fg_color=CARD, corner_radius=12, border_width=1, border_color=BORDER)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 10, 0))
            ctk.CTkFrame(card, fg_color=color, height=4, corner_radius=2).pack(fill="x", padx=14, pady=(12, 0))
            value = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=32, weight="bold"), text_color=color)
            value.pack(anchor="w", padx=16, pady=(6, 0))
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=16)
            ctk.CTkLabel(card, text=hint, text_color=MUTED, font=ctk.CTkFont(size=11)).pack(
                anchor="w", padx=16, pady=(0, 12)
            )
            self.card_values[key] = value

        # --- Barra de filtros
        bar = ctk.CTkFrame(main, fg_color="transparent")
        bar.grid(row=2, column=0, sticky="ew", pady=(4, 8))
        self.filter_btn = ctk.CTkSegmentedButton(bar, values=list(FILTERS), command=lambda _v: self._render_table())
        self.filter_btn.set("Todos")
        self.filter_btn.pack(side="left")
        self.search = ctk.CTkEntry(bar, placeholder_text="Buscar por nombre, ruta, editor o hash…", width=360)
        self.search.pack(side="right")
        self.search.bind("<KeyRelease>", lambda _e: self._render_table())

        # --- Pestañas
        self.tabs = ctk.CTkTabview(main, fg_color=PANEL, segmented_button_selected_color=ACCENT)
        self.tabs.grid(row=3, column=0, sticky="nsew")
        tab_findings = self.tabs.add("Hallazgos")
        tab_conns = self.tabs.add("Conexiones")
        tab_log = self.tabs.add("Registro")

        self.tree = self._make_tree(
            tab_findings,
            (
                ("estado", "Estado", 145),
                ("origen", "Origen", 120),
                ("nombre", "Nombre", 190),
                ("ruta", "Ruta", 250),
                ("editor", "Editor", 130),
                ("vt", "VT", 115),
                ("red", "Red", 50),
            ),
            sortable=True,
        )
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_detail())
        self.tree.bind("<Double-1>", lambda _e: self._open_vt())

        self.conn_tree = self._make_tree(
            tab_conns,
            (
                ("proceso", "Proceso", 160),
                ("pid", "PID", 70),
                ("proto", "Proto", 70),
                ("estado", "Estado", 120),
                ("local", "Local", 200),
                ("remoto", "Remoto", 220),
                ("veredicto", "Veredicto", 120),
            ),
        )

        self.log_box = ctk.CTkTextbox(tab_log, fg_color=CARD, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.pack(fill="both", expand=True, padx=4, pady=4)
        self.log_box.configure(state="disabled")

        # --- Detalle
        detail = ctk.CTkFrame(main, fg_color=PANEL, corner_radius=12)
        detail.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        detail.grid_columnconfigure(0, weight=1)
        self.detail_box = ctk.CTkTextbox(detail, height=150, fg_color=CARD, wrap="word")
        self.detail_box.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        self.detail_box.configure(state="disabled")
        actions = ctk.CTkFrame(detail, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="n", padx=(0, 12), pady=12)
        self.detail_buttons: list[ctk.CTkButton] = []
        for text, cmd in (
            ("Abrir en VirusTotal", self._open_vt),
            ("Copiar SHA-256", self._copy_hash),
            ("Mostrar en el Explorador", self._reveal),
            ("Ignorar esta ruta", lambda: self._whitelist_selected(by_hash=False)),
            ("Ignorar este hash", lambda: self._whitelist_selected(by_hash=True)),
        ):
            b = ctk.CTkButton(actions, text=text, width=200, height=28, fg_color=CARD, hover_color=BORDER, command=cmd)
            b.pack(pady=3)
            self.detail_buttons.append(b)
        self._set_detail(None)

        # --- Barra de estado
        status = ctk.CTkFrame(main, fg_color="transparent")
        status.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        status.grid_columnconfigure(1, weight=1)
        self.status_label = ctk.CTkLabel(status, text="Listo.", text_color=MUTED, anchor="w", width=420)
        self.status_label.grid(row=0, column=0, sticky="w")
        self.progress = ctk.CTkProgressBar(status, progress_color=ACCENT)
        self.progress.grid(row=0, column=1, sticky="ew", padx=(12, 0))
        self.progress.set(0)

    def _make_tree(
        self, parent: Any, columns: tuple[tuple[str, str, int], ...], sortable: bool = False
    ) -> ttk.Treeview:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=4, pady=4)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", style="Triage.Treeview")
        for key, title, width in columns:
            cmd = (lambda k=key: self._sort_by(k)) if sortable else ""
            tree.heading(key, text=title, anchor="w", command=cmd)
            tree.column(key, width=width, minwidth=60, anchor="w", stretch=key in ("ruta", "nombre", "remoto"))
        for st, color in STATUS_COLOR.items():
            tree.tag_configure(st.value, foreground=color)
        tree.tag_configure("odd", background="#1a2332")
        yscroll = ctk.CTkScrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        return tree

    # ============================================================ herramientas
    def _refresh_tools(self) -> None:
        self.tools = env_check.check_all()
        for w in self.tools_frame.winfo_children():
            w.destroy()
        for name, st in self.tools.items():
            row = ctk.CTkFrame(self.tools_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            color = STATUS_COLOR[Status.CLEAN] if st.found else STATUS_COLOR[Status.DETECTED]
            ctk.CTkLabel(row, text="●", text_color=color, width=16).pack(side="left")
            ctk.CTkLabel(row, text=name).pack(side="left", padx=(4, 0))
            if not st.found:
                ctk.CTkButton(
                    row,
                    text="Instalar",
                    width=70,
                    height=24,
                    fg_color=CARD,
                    hover_color=BORDER,
                    command=lambda n=name: self._install_help(n),
                ).pack(side="right")

    def _install_help(self, name: str) -> None:
        info = env_check.TOOLS[name]
        cmd = f"winget install --id {info['winget']} -e --accept-source-agreements"
        if messagebox.askyesno(
            f"Falta {name}",
            f"Instálala desde una terminal con:\n\n{cmd}\n\no descárgala de:\n{info['url']}\n\n"
            "¿Copiar el comando al portapapeles?",
            parent=self,
        ):
            self._to_clipboard(cmd)
            self._set_status("Comando copiado. Pégalo en una terminal y pulsa «Volver a comprobar».")

    # ============================================================ análisis
    def _read_options(self) -> TriageOptions | None:
        raw = self.vt_limit.get().strip()
        limit = None
        if raw:
            if not raw.isdigit():
                messagebox.showerror(
                    "Valor no válido", "El límite de VirusTotal debe ser un número entero.", parent=self
                )
                return None
            limit = int(raw)
        return TriageOptions(
            autoruns=self.var_autoruns.get(),
            scan_user=self.var_scan_user.get(),
            network=self.var_network.get(),
            vt=self.var_vt.get(),
            dry_run=self.var_dry.get(),
            vt_limit=limit,
            config_dir=self.config_dir,
        )

    def _start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        opts = self._read_options()
        if opts is None:
            return
        if not opts.any_collector:
            messagebox.showwarning("Nada que analizar", "Activa al menos un módulo.", parent=self)
            return
        if not self.windows and not opts.dry_run:
            messagebox.showerror(
                "Sistema no compatible", "Fuera de Windows solo funciona el modo demostración.", parent=self
            )
            return
        self.tools = env_check.check_all()
        missing = sorted(n for n in opts.required_tools if not self.tools[n].found)
        if missing:
            self._refresh_tools()
            messagebox.showerror(
                "Faltan herramientas",
                "No se encontraron: " + ", ".join(missing) + ".\n\n"
                "Pulsa «Instalar» junto a cada una en el panel izquierdo, o activa el modo demostración.",
                parent=self,
            )
            return
        load_dotenv(self.env_file, override=True)
        no_key = os.environ.get("VT_API_KEY", "").strip() in ("", PLACEHOLDER_KEY)
        if (
            opts.vt
            and not opts.dry_run
            and no_key
            and messagebox.askyesno(
                "Falta la clave de VirusTotal",
                "No hay API key configurada. ¿Quieres añadirla ahora?\n\nSi no, el análisis seguirá sin VirusTotal.",
                parent=self,
            )
        ):
            self._edit_api_key()

        self.result, self.findings, self.reports = None, [], []
        self._render_table()
        self._render_connections()
        self._update_cards()
        self._set_detail(None)
        self.cancel = threading.Event()
        self._set_running(True)
        self._log("INFO", "Análisis iniciado" + (" (modo demostración)" if opts.dry_run else ""))
        self.worker = threading.Thread(target=self._work, args=(opts,), daemon=True)
        self.worker.start()

    def _work(self, opts: TriageOptions) -> None:
        """Hilo de trabajo: nunca toca widgets, solo envía eventos."""
        try:
            res = TriageEngine(opts, self.tools, QueueReporter(self.events), self.cancel).run()
            self.events.put(("result", res))
        except Cancelled:
            self.events.put(("cancelled",))
        except WhitelistError as e:
            self.events.put(("fatal", str(e)))
        except Exception as e:
            log.exception("Error inesperado en el análisis")
            self.events.put(("fatal", f"{type(e).__name__}: {e}"))

    def _cancel(self) -> None:
        if self.worker and self.worker.is_alive():
            self.cancel.set()
            self._set_status("Cancelando… (autorunsc/sigcheck terminarán su paso actual)")

    def _poll_events(self) -> None:
        try:
            while True:
                self._handle(self.events.get_nowait())
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _handle(self, ev: tuple[Any, ...]) -> None:
        kind = ev[0]
        if kind == "stage":
            self._set_status(ev[1])
            self._indeterminate(True)
        elif kind == "done":
            self._indeterminate(False)
        elif kind == "log":
            self._log(ev[1], ev[2])
        elif kind == "vt_start":
            _, total, cached, new, eta = ev
            extra = f" · ≈{eta / 60:.1f} min" if eta else ""
            self._log("INFO", f"VirusTotal: {total} hashes · {cached} en caché · {new} consultas nuevas{extra}")
            self._indeterminate(False)
            self.progress.set(0)
        elif kind == "vt_progress":
            _, i, total, sha, result, origin = ev
            summary = Finding("", "", "", "", "", "", vt=result).vt_summary
            self.progress.set(i / max(total, 1))
            self._set_status(f"VirusTotal {i}/{total}: {sha[:16]}… → {summary} ({origin})")
            self._log("INFO", f"VT [{i}/{total}] {sha} → {summary} ({origin})")
        elif kind == "vt_wait":
            self._set_status(f"Esperando el límite de VirusTotal: {ev[1]:4.1f} s…")
        elif kind == "result":
            self._finish(ev[1])
        elif kind == "cancelled":
            self._set_running(False)
            self._set_status("Análisis cancelado.")
            self._log("AVISO", "Análisis cancelado por el usuario.")
        elif kind == "fatal":
            self._set_running(False)
            self._set_status("Error.")
            self._log("ERROR", ev[1])
            messagebox.showerror("Error", ev[1], parent=self)

    def _finish(self, res: TriageResult) -> None:
        self.result = res
        self.findings = res.findings
        self._set_running(False)
        self.progress.set(1)
        mode = " · modo demostración" if res.dry_run else ""
        self.subtitle.configure(text=f"{res.host} · {res.started:%d/%m/%Y %H:%M}{mode}")
        self._render_table()
        self._render_connections()
        self._update_cards()

        fmt = FORMATS[self.format_menu.get()]
        if fmt:
            self.reports = report.write_reports(res, self.config_dir / "reportes", fmt)
            for p in self.reports:
                self._log("INFO", f"Informe guardado: {p}")
        self.open_report_btn.configure(state="normal" if self.reports else "disabled")

        c = res.counts()
        self._set_status(
            f"Terminado: {c[Status.DETECTED]} detectados · {c[Status.UNKNOWN]} desconocidos · {c[Status.CLEAN]} limpios."
        )
        for e in res.errors:
            self._log("AVISO", e)
        if c[Status.DETECTED]:
            self.filter_btn.set("Detectados")
            self._render_table()
            self.bell()

    # ============================================================ tabla y detalle
    def _visible(self) -> list[tuple[int, Finding]]:
        wanted = FILTERS[self.filter_btn.get()]
        q = self.search.get().strip().lower()
        rows = []
        for i, f in enumerate(self.findings):
            if wanted and f.status is not wanted:
                continue
            haystack = f"{f.name} {f.path} {f.publisher} {f.signature} {f.sha256}".lower()
            if q and q not in haystack:
                continue
            rows.append((i, f))
        key, reverse = self.sort_key
        sorters = {
            "estado": lambda r: (r[1].status.rank, r[1].name.lower()),
            "origen": lambda r: r[1].source,
            "nombre": lambda r: r[1].name.lower(),
            "ruta": lambda r: r[1].path.lower(),
            "editor": lambda r: r[1].publisher.lower(),
            "vt": lambda r: -((r[1].vt or {}).get("malicious", -1)),
            "red": lambda r: -len(r[1].connections),
        }
        return sorted(rows, key=sorters[key], reverse=reverse)

    def _sort_by(self, key: str) -> None:
        current, reverse = self.sort_key
        self.sort_key = (key, not reverse if current == key else False)
        self._render_table()

    def _render_table(self) -> None:
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for n, (i, f) in enumerate(self._visible()):
            st = f.status
            self.tree.insert(
                "",
                "end",
                iid=str(i),
                values=(
                    f"●  {st.value}",
                    SOURCE_LABEL.get(f.source, f.source),
                    f.name,
                    f.path or "—",
                    f.publisher,
                    f.vt_summary,
                    len(f.connections) or "—",
                ),
                tags=(st.value, "odd") if n % 2 else (st.value,),
            )
        keep = [s for s in selected if self.tree.exists(s)]
        if keep:
            self.tree.selection_set(keep)
        else:
            self._set_detail(None)

    def _render_connections(self) -> None:
        self.conn_tree.delete(*self.conn_tree.get_children())
        for n, (c, st) in enumerate(report.unique_connections(self.findings)):
            self.conn_tree.insert(
                "",
                "end",
                values=(c.process, c.pid, c.protocol, c.state, c.local, c.remote, st.value),
                tags=(st.value, "odd") if n % 2 else (st.value,),
            )
        count = len(self.conn_tree.get_children())
        self.tabs._segmented_button._buttons_dict["Conexiones"].configure(
            text=f"Conexiones ({count})" if count else "Conexiones"
        )

    def _update_cards(self) -> None:
        c = self.result.counts() if self.result else dict.fromkeys(Status, 0)
        self.card_values["detected"].configure(text=str(c[Status.DETECTED]))
        self.card_values["unknown"].configure(text=str(c[Status.UNKNOWN]))
        self.card_values["clean"].configure(text=str(c[Status.CLEAN]))
        self.card_values["whitelist"].configure(text=str(self.result.whitelisted if self.result else 0))

    def _selected(self) -> Finding | None:
        sel = self.tree.selection()
        return self.findings[int(sel[0])] if sel else None

    def _show_detail(self) -> None:
        self._set_detail(self._selected())

    def _set_detail(self, f: Finding | None) -> None:
        self.detail_box.configure(state="normal")
        self.detail_box.delete("1.0", "end")
        if f is None:
            self.detail_box.insert("end", "Selecciona un elemento de la tabla para ver su detalle.")
        else:
            vt = f.vt or {}
            lines = [
                f"{f.status.value} — {f.name}",
                f"Ruta: {f.path or '—'}",
                f"Ubicación: {f.location or '—'}    Categoría: {f.category or '—'}",
                f"Editor: {f.publisher}    Firma: {f.signature}",
                f"SHA-256: {f.sha256 or 'no disponible'}",
            ]
            if vt.get("found"):
                label = f" · etiqueta: {vt['label']}" if vt.get("label") else ""
                lines.append(
                    f"VirusTotal: {vt.get('malicious', 0)} maliciosos, {vt.get('suspicious', 0)} sospechosos "
                    f"de {vt.get('total', 0)} motores{label}"
                )
            elif vt:
                lines.append(f"VirusTotal: {f.vt_summary}")
            lines += [f"Conexión: {c.protocol} {c.local} → {c.remote} ({c.state}, PID {c.pid})" for c in f.connections]
            self.detail_box.insert("end", "\n".join(lines))
        self.detail_box.configure(state="disabled")
        state = "normal" if f else "disabled"
        for b in self.detail_buttons:
            b.configure(state=state)
        if f and not f.sha256:
            self.detail_buttons[0].configure(state="disabled")
            self.detail_buttons[1].configure(state="disabled")
            self.detail_buttons[4].configure(state="disabled")
        if f and not self.windows:
            self.detail_buttons[2].configure(state="disabled")

    # ============================================================ acciones
    def _open_vt(self) -> None:
        f = self._selected()
        if f and f.sha256:
            webbrowser.open(GUI_URL.format(f.sha256))

    def _copy_hash(self) -> None:
        f = self._selected()
        if f and f.sha256:
            self._to_clipboard(f.sha256)
            self._set_status("SHA-256 copiado al portapapeles.")

    def _reveal(self) -> None:
        f = self._selected()
        if not f or not f.path:
            return
        path = Path(expand_win_vars(f.path.strip('"')))
        if not path.exists():
            messagebox.showinfo("No encontrado", f"El archivo ya no existe:\n{path}", parent=self)
            return
        subprocess.Popen(["explorer", f"/select,{path}"])

    def _whitelist_selected(self, by_hash: bool) -> None:
        f = self._selected()
        if not f or self.result is None:
            return
        value = f.sha256 if by_hash else f.path
        what = "el hash" if by_hash else "la ruta"
        if not messagebox.askyesno(
            "Añadir a la lista blanca",
            f"Se ignorará {what} en próximos análisis:\n\n{value}\n\n¿Continuar?",
            parent=self,
        ):
            return
        file = self.config_dir / "whitelist.json"
        try:
            add_to_whitelist(file, sha256=value) if by_hash else add_to_whitelist(file, path=value)
        except (OSError, ValueError) as e:
            messagebox.showerror("No se pudo guardar", str(e), parent=self)
            return
        wl = Whitelist(hashes=[value]) if by_hash else Whitelist(paths=[value])
        for section, items in self.result.sections.items():
            kept, removed = wl.filter(items)
            self.result.sections[section] = kept
            self.result.whitelisted += removed
        self.findings = self.result.findings
        self._render_table()
        self._render_connections()
        self._update_cards()
        self._log("INFO", f"Añadido a whitelist.json: {value}")
        self._set_status("Añadido a la lista blanca.")

    def _edit_api_key(self) -> None:
        dlg = SecretDialog(self, os.environ.get("VT_API_KEY", ""))
        self.wait_window(dlg)
        if dlg.value is None:
            return
        self.env_file.parent.mkdir(parents=True, exist_ok=True)
        self.env_file.touch(exist_ok=True)
        set_key(str(self.env_file), "VT_API_KEY", dlg.value, quote_mode="never")
        os.environ["VT_API_KEY"] = dlg.value
        self._log("INFO", f"Clave de VirusTotal guardada en {self.env_file}")
        self._set_status("Clave de VirusTotal guardada.")

    def _open_whitelist(self) -> None:
        file = self.config_dir / "whitelist.json"
        try:
            Whitelist.load(file)  # la crea con la plantilla si no existe
        except WhitelistError as e:
            messagebox.showwarning("whitelist.json", str(e), parent=self)
        open_path(file)

    def _open_reports_dir(self) -> None:
        folder = self.config_dir / "reportes"
        folder.mkdir(parents=True, exist_ok=True)
        open_path(folder)

    def _open_report(self) -> None:
        if self.reports:
            open_path(self.reports[0])

    def _relaunch_admin(self) -> None:
        if env_check.relaunch_as_admin(["--config-dir", str(self.config_dir)]):
            self._on_close()
        else:
            messagebox.showwarning("Elevación cancelada", "No se pudo reiniciar como administrador.", parent=self)

    # ============================================================ helpers
    def _set_running(self, running: bool) -> None:
        self.run_btn.configure(
            state="disabled" if running else "normal", text="Analizando…" if running else "▶  Analizar"
        )
        self.cancel_btn.configure(state="normal" if running else "disabled")
        if running:
            self.open_report_btn.configure(state="disabled")
            self.progress.set(0)
        else:
            self._indeterminate(False)
            if not self.reports:
                self.open_report_btn.configure(state="disabled")

    def _indeterminate(self, on: bool) -> None:
        if on:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate")

    def _set_status(self, text: str) -> None:
        self.status_label.configure(text=text)

    def _log(self, level: str, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{datetime.now():%H:%M:%S}  {level:<5}  {text}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _to_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    def _on_close(self) -> None:
        self.cancel.set()
        self.destroy()


def main(config_dir: Path | None = None, argv: list[str] | None = None) -> int:
    if config_dir is None:
        p = argparse.ArgumentParser(prog="win11-triage-gui", description="Interfaz gráfica de win11-triage.")
        p.add_argument("--config-dir", type=Path, help="carpeta con .env, whitelist.json y vt_cache.json")
        config_dir = p.parse_args(argv).config_dir
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = TriageApp((config_dir or default_config_dir()).resolve())
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
