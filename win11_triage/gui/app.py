"""Ventana principal de win11-triage.

El análisis corre en un hilo aparte (TriageEngine); la interfaz solo se actualiza desde el
hilo principal, leyendo una cola de eventos cada 100 ms.
"""

from __future__ import annotations

import contextlib
import csv
import logging
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

import customtkinter as ctk
from dotenv import load_dotenv, set_key

from .. import __version__, collectors_live, env_check, report
from ..engine import PLACEHOLDER_KEY, Reporter, TriageEngine, TriageOptions
from ..enrich import pe_static, yara_scan
from ..models import Cancelled, Finding, Status
from ..report import TriageResult
from ..rules.attack import attack_url, technique_name
from ..utils import expand_win_vars
from ..virustotal import GUI_URL
from ..whitelist import Whitelist, WhitelistError, add_to_whitelist
from . import history, settings
from .theme import (
    ACCENT,
    ACCENT_HOVER,
    BG,
    BORDER,
    CARD,
    CARD_ALT,
    CYAN,
    ICON_ICO,
    ICON_SMALL,
    MUTED,
    PANEL,
    PURPLE,
    SELECTED,
    STATUS_COLOR,
    TEXT,
    score_color,
)
from .widgets import AboutDialog, BarChart, DonutChart, ScoreGauge, SecretDialog, StatCard, dark_menu, load_logo, toast

log = logging.getLogger(__name__)

FILTERS = {"Todos": None, "Detectados": Status.DETECTED, "Desconocidos": Status.UNKNOWN, "Limpios": Status.CLEAN}
FORMATS = {"HTML": "html", "Markdown": "md", "JSON": "json", "Todos (HTML+MD+JSON)": "all", "No guardar": None}
SOURCE_LABEL = report.SOURCE_LABEL
MODULES = (
    ("autoruns", "Persistencia", "Programas que arrancan solos (autorunsc)"),
    ("scan_user", "Carpetas de usuario", "Ejecutables sin firma en Temp y AppData"),
    ("processes", "Procesos en ejecución", "Rutas raras, suplantación, Office → consola"),
    ("events", "Eventos de Windows", "Servicios y tareas nuevos, detecciones de Defender"),
    ("network", "Conexiones de red", "Qué proceso sospechoso habla con el exterior"),
    ("static", "Análisis de contenido", "Empaquetadores, imports de inyección, YARA"),
    ("vt", "VirusTotal", "Reputación de cada hash (15 s por consulta nueva)"),
)
PRESETS = {
    "Rápido": {"autoruns", "scan_user", "processes", "network"},
    "Completo": {m for m, _, _ in MODULES},
}


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


class TriageApp(ctk.CTk):
    def __init__(self, config_dir: Path) -> None:
        super().__init__()
        self.config_dir = config_dir
        self.env_file = config_dir / ".env"
        self.reports_dir = config_dir / "reportes"
        load_dotenv(self.env_file, override=True)
        self.prefs = settings.load(config_dir)

        self.events: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self.cancel_flag = threading.Event()
        self.worker: threading.Thread | None = None
        self.result: TriageResult | None = None
        self.findings: list[Finding] = []
        self.new_keys: set[str] = set()
        self.has_previous = False
        self.reports: list[Path] = []
        self.history_entries: list[history.HistoryEntry] = []
        self.sort_key = ("estado", False)
        self.started_at = 0.0
        self.tools = env_check.check_all()
        self.windows = env_check.is_windows()
        self.admin = env_check.is_admin()

        self.title(f"win11-triage {__version__}")
        self.geometry(self.prefs.get("geometry") or "1440x900")
        self.minsize(1200, 760)
        self.configure(fg_color=BG)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._ui_icon()

        self._ui_style()
        self._ui_sidebar()
        self._ui_main()
        self._ui_shortcuts()
        self.refresh_tools()
        self.refresh_history()
        self.render_all()
        self.set_running(False)
        self.log_line("INFO", f"Carpeta de configuración: {self.config_dir}")
        if not self.windows:
            self.log_line("AVISO", "Este sistema no es Windows: solo está disponible el modo demostración.")

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(100, self.poll_events)

    # ================================================================= construcción
    def _ui_icon(self) -> None:
        try:
            if sys.platform == "win32" and ICON_ICO.exists():
                self.iconbitmap(str(ICON_ICO))
            elif ICON_SMALL.exists():
                self._icon_img = tk.PhotoImage(file=str(ICON_SMALL))
                self.iconphoto(True, self._icon_img)
        except tk.TclError:
            log.debug("No se pudo aplicar el icono de la ventana", exc_info=True)

    def _ui_style(self) -> None:
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
        style.map("Triage.Treeview", background=[("selected", SELECTED)], foreground=[("selected", "#ffffff")])
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

    def _ui_section(self, parent: Any, text: str) -> None:
        ctk.CTkLabel(parent, text=text.upper(), text_color=MUTED, font=ctk.CTkFont(size=11, weight="bold")).pack(
            anchor="w", padx=18, pady=(18, 6)
        )

    def _ui_small_button(self, parent: Any, text: str, cmd: Any, **kw: Any) -> ctk.CTkButton:
        return ctk.CTkButton(parent, text=text, height=30, fg_color=CARD, hover_color=BORDER, command=cmd, **kw)

    def _ui_sidebar(self) -> None:
        side = ctk.CTkScrollableFrame(self, width=300, corner_radius=0, fg_color=PANEL)
        side.grid(row=0, column=0, rowspan=2, sticky="nsw")

        brand = ctk.CTkFrame(side, fg_color="transparent")
        brand.pack(fill="x", padx=18, pady=(18, 0))
        self.logo = load_logo(46)
        if self.logo:
            ctk.CTkLabel(brand, text="", image=self.logo).pack(side="left")
        names = ctk.CTkFrame(brand, fg_color="transparent")
        names.pack(side="left", padx=10)
        ctk.CTkLabel(names, text="win11-triage", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(names, text=f"Triaje defensivo · v{__version__}", text_color=MUTED).pack(anchor="w")

        if self.windows:
            ok = self.admin
            ctk.CTkLabel(
                side,
                text="● Administrador" if ok else "● Sin privilegios de administrador",
                text_color=STATUS_COLOR[Status.CLEAN if ok else Status.UNKNOWN],
            ).pack(anchor="w", padx=18, pady=(12, 0))
            if not ok:
                self._ui_small_button(side, "Reiniciar como administrador", self.relaunch_admin).pack(
                    fill="x", padx=18, pady=(6, 0)
                )

        # ---- módulos
        self._ui_section(side, "Módulos")
        presets = ctk.CTkFrame(side, fg_color="transparent")
        presets.pack(fill="x", padx=18, pady=(0, 6))
        for name in PRESETS:
            self._ui_small_button(presets, name, lambda n=name: self.apply_preset(n), width=125).pack(
                side="left", padx=(0, 8)
            )
        self.module_vars: dict[str, ctk.BooleanVar] = {}
        for key, title, desc in MODULES:
            var = ctk.BooleanVar(value=self.prefs["modules"].get(key, True))
            self.module_vars[key] = var
            ctk.CTkCheckBox(side, text=title, variable=var, font=ctk.CTkFont(weight="bold")).pack(
                anchor="w", padx=18, pady=(7, 0)
            )
            ctk.CTkLabel(
                side,
                text=desc,
                text_color=MUTED,
                font=ctk.CTkFont(size=11),
                anchor="w",
                justify="left",
                wraplength=220,
            ).pack(anchor="w", fill="x", padx=(46, 12))
            if key == "events":
                row = ctk.CTkFrame(side, fg_color="transparent")
                row.pack(anchor="w", padx=(46, 0), pady=(2, 0))
                ctk.CTkLabel(row, text="Últimos", text_color=MUTED, font=ctk.CTkFont(size=11)).pack(side="left")
                self.days_menu = ctk.CTkOptionMenu(row, values=["1", "7", "30", "90"], width=70, height=24)
                self.days_menu.set(str(self.prefs.get("event_days", 7)))
                self.days_menu.pack(side="left", padx=6)
                ctk.CTkLabel(row, text="días", text_color=MUTED, font=ctk.CTkFont(size=11)).pack(side="left")

        # ---- opciones
        self._ui_section(side, "Opciones")
        self.var_dry = ctk.BooleanVar(value=not self.windows)
        sw = ctk.CTkSwitch(side, text="Modo demostración", variable=self.var_dry)
        sw.pack(anchor="w", padx=18)
        if not self.windows:
            sw.configure(state="disabled")
        ctk.CTkLabel(
            side, text="Datos de ejemplo, sin red ni herramientas", text_color=MUTED, font=ctk.CTkFont(size=11)
        ).pack(anchor="w", padx=18)
        ctk.CTkLabel(side, text="Límite de consultas nuevas a VirusTotal").pack(anchor="w", padx=18, pady=(10, 2))
        self.vt_limit = ctk.CTkEntry(side, placeholder_text="Sin límite")
        self.vt_limit.pack(fill="x", padx=18)
        if self.prefs.get("vt_limit"):
            self.vt_limit.insert(0, str(self.prefs["vt_limit"]))
        ctk.CTkLabel(side, text="Guardar informe como").pack(anchor="w", padx=18, pady=(10, 2))
        self.format_menu = ctk.CTkOptionMenu(side, values=list(FORMATS))
        self.format_menu.set(self.prefs.get("format") if self.prefs.get("format") in FORMATS else "HTML")
        self.format_menu.pack(fill="x", padx=18)

        # ---- acciones
        self.run_btn = ctk.CTkButton(
            side,
            text="▶  Analizar",
            height=44,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            command=self.start,
        )
        self.run_btn.pack(fill="x", padx=18, pady=(20, 6))
        self.cancel_btn = ctk.CTkButton(
            side, text="■  Cancelar", height=34, fg_color=CARD, hover_color=BORDER, command=self.cancel
        )
        self.cancel_btn.pack(fill="x", padx=18)

        # ---- componentes
        self._ui_section(side, "Herramientas y componentes")
        self.tools_frame = ctk.CTkFrame(side, fg_color="transparent")
        self.tools_frame.pack(fill="x", padx=18)
        self._ui_small_button(side, "Volver a comprobar  (F5)", self.refresh_tools).pack(fill="x", padx=18, pady=(6, 0))

        # ---- configuración
        self._ui_section(side, "Configuración")
        self.vt_status = ctk.CTkLabel(side, text="", anchor="w")
        self.vt_status.pack(anchor="w", padx=18)
        for text, cmd in (
            ("Clave de VirusTotal…", self.edit_api_key),
            ("Editar lista blanca", self.open_whitelist),
            ("Reglas YARA propias", self.open_yara_dir),
            ("Carpeta de informes", self.open_reports_dir),
            ("Acerca de", lambda: AboutDialog(self)),
        ):
            self._ui_small_button(side, text, cmd, anchor="w").pack(fill="x", padx=18, pady=3)
        ctk.CTkLabel(side, text="").pack(pady=6)

    def _ui_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew", padx=22, pady=(16, 0))
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        # ---- cabecera
        head = ctk.CTkFrame(main, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(head, text="Resultados", font=ctk.CTkFont(size=24, weight="bold")).pack(side="left")
        self.subtitle = ctk.CTkLabel(head, text="Elige los módulos y pulsa Analizar (Ctrl+R).", text_color=MUTED)
        self.subtitle.pack(side="left", padx=14, pady=(6, 0))
        self.open_report_btn = ctk.CTkButton(
            head, text="Abrir informe", width=130, fg_color=CARD, hover_color=BORDER, command=self.open_report
        )
        self.open_report_btn.pack(side="right")
        self.export_btn = ctk.CTkButton(head, text="Exportar ▾", width=120, fg_color=CARD, hover_color=BORDER)
        self.export_btn.configure(command=self.show_export_menu)
        self.export_btn.pack(side="right", padx=8)

        # ---- tarjetas
        cards = ctk.CTkFrame(main, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", pady=(12, 10))
        specs = (
            ("detected", "Detectados", "VT o score ≥ 70", STATUS_COLOR[Status.DETECTED]),
            ("unknown", "Sospechosos / sin firma", "Revisar manualmente", STATUS_COLOR[Status.UNKNOWN]),
            ("clean", "Limpios", "Firma válida o VT limpio", STATUS_COLOR[Status.CLEAN]),
            ("new", "Nuevos", "Desde el análisis anterior", PURPLE),
            ("whitelist", "En lista blanca", "Ignorados por ti", MUTED),
        )
        self.cards: dict[str, StatCard] = {}
        for i, (key, title, hint, color) in enumerate(specs):
            cards.grid_columnconfigure(i, weight=1, uniform="cards")
            card = StatCard(cards, title, hint, color)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 10, 0))
            self.cards[key] = card

        # ---- pestañas
        self.tabs = ctk.CTkTabview(main, fg_color=PANEL, segmented_button_selected_color=ACCENT)
        self.tabs.grid(row=2, column=0, sticky="nsew")
        self._ui_tab_dashboard(self.tabs.add("Panel"))
        self._ui_tab_findings(self.tabs.add("Hallazgos"))
        self._ui_tab_connections(self.tabs.add("Conexiones"))
        self._ui_tab_history(self.tabs.add("Historial"))
        self._ui_tab_log(self.tabs.add("Registro"))

        # ---- barra de estado
        status = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0, height=36)
        status.grid(row=1, column=1, sticky="ew")
        status.grid_columnconfigure(2, weight=1)
        self.status_label = ctk.CTkLabel(status, text="Listo.", text_color=MUTED, anchor="w", width=460)
        self.status_label.grid(row=0, column=0, sticky="w", padx=(22, 8), pady=6)
        self.elapsed_label = ctk.CTkLabel(status, text="", text_color=MUTED, width=70)
        self.elapsed_label.grid(row=0, column=1)
        self.progress = ctk.CTkProgressBar(status, progress_color=ACCENT)
        self.progress.grid(row=0, column=2, sticky="ew", padx=12)
        self.progress.set(0)
        ctk.CTkLabel(
            status,
            text="Ctrl+R analizar · Esc cancelar · Ctrl+F buscar · Ctrl+E exportar CSV",
            text_color=MUTED,
            font=ctk.CTkFont(size=11),
        ).grid(row=0, column=3, padx=(0, 22))

    def _ui_card(self, parent: Any, title: str) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12)
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=14, pady=(10, 0))
        return frame

    def _ui_tab_dashboard(self, tab: Any) -> None:
        tab.grid_columnconfigure((0, 1, 2), weight=1, uniform="dash")
        tab.grid_rowconfigure((0, 1), weight=1)

        c1 = self._ui_card(tab, "Distribución de veredictos")
        c1.grid(row=0, column=0, sticky="nsew", padx=(4, 6), pady=(4, 6))
        self.donut = DonutChart(c1, height=170)
        self.donut.pack(fill="both", expand=True, padx=8, pady=8)

        c2 = self._ui_card(tab, "Puntuación máxima")
        c2.grid(row=0, column=1, sticky="nsew", padx=6, pady=(4, 6))
        self.gauge = ScoreGauge(c2, height=170)
        self.gauge.pack(fill="both", expand=True, padx=8, pady=8)

        c3 = self._ui_card(tab, "Elementos sospechosos por origen")
        c3.grid(row=0, column=2, sticky="nsew", padx=(6, 4), pady=(4, 6))
        self.by_source = BarChart(c3, height=170, limit=5, empty="Sin elementos sospechosos")
        self.by_source.pack(fill="both", expand=True, padx=8, pady=8)

        c4 = self._ui_card(tab, "Prioriza esto primero")
        c4.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=(4, 6), pady=(6, 4))
        self.priority_tree = self._ui_tree(
            c4,
            (
                ("n", "#", 36),
                ("score", "Score", 60),
                ("origen", "Origen", 110),
                ("nombre", "Nombre", 190),
                ("why", "Por qué", 420),
            ),
            stretch=("why",),
            height=5,
        )
        self.priority_tree.bind("<Double-1>", lambda _e: self.jump_to_priority())

        c5 = self._ui_card(tab, "Técnicas MITRE ATT&CK")
        c5.grid(row=1, column=2, sticky="nsew", padx=(6, 4), pady=(6, 4))
        self.attack_chart = BarChart(c5, height=170, limit=6, empty="Sin técnicas observadas")
        self.attack_chart.pack(fill="both", expand=True, padx=8, pady=8)

    def _ui_tab_findings(self, tab: Any) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.filter_btn = ctk.CTkSegmentedButton(bar, values=list(FILTERS), command=lambda _v: self.render_table())
        self.filter_btn.set("Todos")
        self.filter_btn.pack(side="left")
        self.only_new = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(bar, text="Solo nuevos", variable=self.only_new, command=self.render_table).pack(
            side="left", padx=14
        )
        self.search = ctk.CTkEntry(bar, placeholder_text="Buscar nombre, ruta, editor, hash o técnica…", width=360)
        self.search.pack(side="right")
        self.search.bind("<KeyRelease>", lambda _e: self.render_table())

        holder = ctk.CTkFrame(tab, fg_color="transparent")
        holder.grid(row=1, column=0, sticky="nsew")
        self.tree = self._ui_tree(
            holder,
            (
                ("estado", "Estado", 130),
                ("score", "Score", 60),
                ("origen", "Origen", 110),
                ("nombre", "Nombre", 170),
                ("ruta", "Ruta", 250),
                ("why", "Por qué", 280),
                ("vt", "VT", 90),
                ("red", "Red", 46),
                ("nuevo", "", 70),
            ),
            stretch=("ruta", "why"),
            sortable=True,
        )
        self.tree.tag_configure("new", background="#241a3a")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_detail())
        self.tree.bind("<Double-1>", lambda _e: self.open_vt())
        self.tree.bind("<Button-3>", self.popup_finding_menu)
        self.empty_label = ctk.CTkLabel(holder, text="", text_color=MUTED, font=ctk.CTkFont(size=14), fg_color=CARD)

        detail = ctk.CTkFrame(tab, fg_color=CARD, corner_radius=12)
        detail.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        detail.grid_columnconfigure(0, weight=1)
        self.detail_box = ctk.CTkTextbox(detail, height=170, fg_color=CARD_ALT, wrap="word", font=ctk.CTkFont(size=12))
        self.detail_box.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        for tag, color in (
            ("title", TEXT),
            ("muted", MUTED),
            ("pos", STATUS_COLOR[Status.UNKNOWN]),
            ("neg", STATUS_COLOR[Status.CLEAN]),
            ("red", STATUS_COLOR[Status.DETECTED]),
        ):
            self.detail_box.tag_config(tag, foreground=color)
        self.detail_box.configure(state="disabled")
        actions = ctk.CTkFrame(detail, fg_color="transparent")
        actions.grid(row=0, column=1, sticky="n", padx=(0, 10), pady=10)
        self.detail_buttons: dict[str, ctk.CTkButton] = {}
        for key, text, cmd in (
            ("vt", "Abrir en VirusTotal", self.open_vt),
            ("hash", "Copiar SHA-256", self.copy_hash),
            ("path", "Copiar ruta", self.copy_path),
            ("reveal", "Mostrar en el Explorador", self.reveal),
            ("attack", "Ver técnica ATT&CK", self.open_attack),
            ("wl_path", "Ignorar esta ruta", lambda: self.whitelist_selected(by_hash=False)),
            ("wl_hash", "Ignorar este hash", lambda: self.whitelist_selected(by_hash=True)),
        ):
            b = ctk.CTkButton(actions, text=text, width=200, height=26, fg_color=PANEL, hover_color=BORDER, command=cmd)
            b.pack(pady=2)
            self.detail_buttons[key] = b

    def _ui_tab_connections(self, tab: Any) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        holder = ctk.CTkFrame(tab, fg_color="transparent")
        holder.grid(row=0, column=0, sticky="nsew")
        self.conn_tree = self._ui_tree(
            holder,
            (
                ("proceso", "Proceso", 160),
                ("pid", "PID", 70),
                ("proto", "Proto", 60),
                ("estado", "Estado", 120),
                ("local", "Local", 200),
                ("remoto", "Remoto", 220),
                ("veredicto", "Veredicto", 120),
            ),
            stretch=("remoto",),
        )
        self.conn_tree.bind("<Button-3>", self.popup_connection_menu)
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self._ui_small_button(bar, "Buscar IP en VirusTotal", self.lookup_ip).pack(side="left")
        self._ui_small_button(bar, "Copiar IP remota", self.copy_ip).pack(side="left", padx=8)
        ctk.CTkLabel(bar, text="Solo conexiones externas de procesos señalados.", text_color=MUTED).pack(side="right")

    def _ui_tab_history(self, tab: Any) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        holder = ctk.CTkFrame(tab, fg_color="transparent")
        holder.grid(row=0, column=0, sticky="nsew")
        self.history_tree = self._ui_tree(
            holder,
            (
                ("fecha", "Fecha", 150),
                ("equipo", "Equipo", 140),
                ("modo", "Modo", 120),
                ("det", "Detectados", 100),
                ("unk", "Sospechosos", 110),
                ("ok", "Limpios", 90),
                ("total", "Total", 80),
                ("max", "Score máx.", 90),
            ),
            stretch=("equipo",),
        )
        self.history_tree.bind("<Double-1>", lambda _e: self.load_history_entry())
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self._ui_small_button(bar, "Cargar análisis", self.load_history_entry).pack(side="left")
        self._ui_small_button(bar, "Abrir informe", self.open_history_report).pack(side="left", padx=8)
        self._ui_small_button(bar, "Actualizar", self.refresh_history).pack(side="left")
        self._ui_small_button(bar, "Abrir carpeta", self.open_reports_dir).pack(side="left", padx=8)
        ctk.CTkLabel(bar, text="Se listan los informes JSON de la carpeta de informes.", text_color=MUTED).pack(
            side="right"
        )

    def _ui_tab_log(self, tab: Any) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        self.log_box = ctk.CTkTextbox(tab, fg_color=CARD, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self.log_box.configure(state="disabled")
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self._ui_small_button(bar, "Copiar registro", lambda: self.to_clipboard(self.log_box.get("1.0", "end"))).pack(
            side="left"
        )
        self._ui_small_button(bar, "Limpiar", self.clear_log).pack(side="left", padx=8)

    def _ui_tree(
        self,
        parent: Any,
        columns: tuple[tuple[str, str, int], ...],
        stretch: tuple[str, ...] = (),
        sortable: bool = False,
        height: int | None = None,
    ) -> ttk.Treeview:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=4, pady=4)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        kw = {"height": height} if height else {}
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", style="Triage.Treeview", **kw)
        for key, title, width in columns:
            cmd = (lambda k=key: self.sort_by(k)) if sortable else ""
            tree.heading(key, text=title, anchor="w", command=cmd)
            tree.column(key, width=width, minwidth=36, anchor="w", stretch=key in stretch)
        for st, color in STATUS_COLOR.items():
            tree.tag_configure(st.value, foreground=color)
        tree.tag_configure("odd", background=CARD_ALT)
        yscroll = ctk.CTkScrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        return tree

    def _ui_shortcuts(self) -> None:
        self.bind("<Control-r>", lambda _e: self.start())
        self.bind("<Control-R>", lambda _e: self.start())
        self.bind("<Escape>", lambda _e: self.cancel())
        self.bind("<F5>", lambda _e: self.refresh_tools())
        self.bind("<Control-f>", lambda _e: self.focus_search())
        self.bind("<Control-e>", lambda _e: self.export_csv())
        self.bind("<Control-o>", lambda _e: self.open_report())
        for i, name in enumerate(("Panel", "Hallazgos", "Conexiones", "Historial", "Registro"), 1):
            self.bind(f"<Control-Key-{i}>", lambda _e, n=name: self.tabs.set(n))

    # ================================================================= herramientas
    def refresh_tools(self) -> None:
        self.tools = env_check.check_all()
        for w in self.tools_frame.winfo_children():
            w.destroy()
        rows = [
            (name, st.found, (lambda n=name: self.install_help(n)) if not st.found else None)
            for name, st in self.tools.items()
        ]
        rows += [
            ("psutil (procesos/red)", collectors_live.available(), None),
            ("pefile (análisis PE)", pe_static.available(), None),
            ("YARA (opcional)", yara_scan.available(), None if yara_scan.available() else self.yara_help),
        ]
        missing = [n for n, st in self.tools.items() if not st.found]
        if missing and env_check.winget_available():
            self._ui_small_button(
                self.tools_frame, f"Instalar las {len(missing)} que faltan (winget)", self.install_missing
            ).pack(fill="x", pady=(0, 6))
        for name, ok, fix in rows:
            row = ctk.CTkFrame(self.tools_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)
            color = (
                STATUS_COLOR[Status.CLEAN] if ok else STATUS_COLOR[Status.DETECTED if fix is None else Status.UNKNOWN]
            )
            ctk.CTkLabel(row, text="●", text_color=color, width=16).pack(side="left")
            ctk.CTkLabel(row, text=name).pack(side="left", padx=(4, 0))
            if fix:
                ctk.CTkButton(
                    row, text="Instalar", width=70, height=22, fg_color=CARD, hover_color=BORDER, command=fix
                ).pack(side="right")
        self.update_vt_status()

    def install_missing(self) -> None:
        missing = [n for n, st in self.tools.items() if not st.found]
        if not missing or (self.worker and self.worker.is_alive()):
            return
        if not messagebox.askyesno(
            "Instalar herramientas",
            "Se instalarán con winget (Microsoft Store/Sysinternals):\n\n"
            + "\n".join(f"• {n}  ({env_check.TOOLS[n]['winget']})" for n in missing)
            + "\n\nPuede tardar uno o dos minutos. ¿Continuar?",
            parent=self,
        ):
            return

        def work() -> None:
            for n in missing:
                self.events.put(("stage", f"Instalando {n} con winget…"))
                ok, out = env_check.winget_install(n)
                self.events.put(
                    ("log", "INFO" if ok else "ERROR", f"winget {n}: {'instalada' if ok else 'falló'} {out}")
                )
            self.events.put(("done",))
            self.events.put(("tools_refresh",))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.set_running(True)
        self.run_btn.configure(text="Instalando…")

    def update_vt_status(self) -> None:
        has_key = os.environ.get("VT_API_KEY", "").strip() not in ("", PLACEHOLDER_KEY)
        self.vt_status.configure(
            text="● Clave de VirusTotal configurada" if has_key else "● Sin clave de VirusTotal",
            text_color=STATUS_COLOR[Status.CLEAN if has_key else Status.UNKNOWN],
        )

    def install_help(self, name: str) -> None:
        info = env_check.TOOLS[name]
        cmd = f"winget install --id {info['winget']} -e --accept-source-agreements"
        if messagebox.askyesno(
            f"Falta {name}",
            f"Instálala desde una terminal con:\n\n{cmd}\n\no descárgala de:\n{info['url']}\n\n¿Copiar el comando?",
            parent=self,
        ):
            self.to_clipboard(cmd)
            toast(self, "Comando copiado. Pégalo en una terminal y pulsa F5.")

    def yara_help(self) -> None:
        cmd = 'pip install "win11-triage[yara]"'
        if messagebox.askyesno(
            "YARA no instalado",
            f"El análisis de contenido funciona sin YARA (solo PE).\nPara activar YARA:\n\n{cmd}\n\n¿Copiar el comando?",
            parent=self,
        ):
            self.to_clipboard(cmd)
            toast(self, "Comando copiado.")

    def apply_preset(self, name: str) -> None:
        wanted = PRESETS[name]
        for key, var in self.module_vars.items():
            var.set(key in wanted)
        toast(self, f"Perfil «{name}» aplicado.")

    # ================================================================= análisis
    def read_options(self) -> TriageOptions | None:
        raw = self.vt_limit.get().strip()
        if raw and not raw.isdigit():
            messagebox.showerror("Valor no válido", "El límite de VirusTotal debe ser un número entero.", parent=self)
            return None
        m = {k: v.get() for k, v in self.module_vars.items()}
        return TriageOptions(
            autoruns=m["autoruns"],
            scan_user=m["scan_user"],
            processes=m["processes"],
            events=m["events"],
            network=m["network"],
            static=m["static"],
            vt=m["vt"],
            dry_run=self.var_dry.get(),
            vt_limit=int(raw) if raw else None,
            event_days=int(self.days_menu.get()),
            config_dir=self.config_dir,
        )

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        opts = self.read_options()
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
            self.refresh_tools()
            messagebox.showerror(
                "Faltan herramientas",
                "No se encontraron: " + ", ".join(missing) + ".\n\nPulsa «Instalar» en el panel izquierdo "
                "o activa el modo demostración.",
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
            self.edit_api_key()

        self.save_prefs()
        self.result, self.findings, self.reports, self.new_keys, self.has_previous = None, [], [], set(), False
        self.render_all()
        self.cancel_flag = threading.Event()
        self.set_running(True)
        self.log_line("INFO", "Análisis iniciado" + (" (modo demostración)" if opts.dry_run else ""))
        self.worker = threading.Thread(target=self._work, args=(opts,), daemon=True)
        self.worker.start()

    def _work(self, opts: TriageOptions) -> None:
        """Hilo de trabajo: nunca toca widgets, solo envía eventos."""
        try:
            res = TriageEngine(opts, self.tools, QueueReporter(self.events), self.cancel_flag).run()
            self.events.put(("result", res))
        except Cancelled:
            self.events.put(("cancelled",))
        except WhitelistError as e:
            self.events.put(("fatal", str(e)))
        except Exception as e:
            log.exception("Error inesperado en el análisis")
            self.events.put(("fatal", f"{type(e).__name__}: {e}"))

    def cancel(self) -> None:
        if self.worker and self.worker.is_alive():
            self.cancel_flag.set()
            self.set_status("Cancelando… (las herramientas externas terminan su paso actual)")

    def poll_events(self) -> None:
        with contextlib.suppress(queue.Empty):
            while True:
                self.handle_event(self.events.get_nowait())
        if self.worker and self.worker.is_alive():
            self.elapsed_label.configure(text=f"{time.monotonic() - self.started_at:4.0f} s")
        self.after(100, self.poll_events)

    def handle_event(self, ev: tuple[Any, ...]) -> None:
        kind = ev[0]
        if kind == "stage":
            self.set_status(ev[1])
            self.indeterminate(True)
        elif kind == "done":
            self.indeterminate(False)
        elif kind == "log":
            self.log_line(ev[1], ev[2])
            if ev[1] == "INFO":
                self.set_status(ev[2])
        elif kind == "vt_start":
            _, total, cached, new, eta = ev
            extra = f" · ≈{eta / 60:.1f} min" if eta else ""
            self.log_line("INFO", f"VirusTotal: {total} hashes · {cached} en caché · {new} consultas nuevas{extra}")
            self.indeterminate(False)
            self.progress.set(0)
        elif kind == "vt_progress":
            _, i, total, sha, result, origin = ev
            summary = Finding("", "", "", "", "", "", vt=result).vt_summary
            self.progress.set(i / max(total, 1))
            self.set_status(f"VirusTotal {i}/{total}: {sha[:16]}… → {summary} ({origin})")
            self.log_line("INFO", f"VT [{i}/{total}] {sha} → {summary} ({origin})")
        elif kind == "vt_wait":
            self.set_status(f"Esperando el límite de VirusTotal: {ev[1]:4.1f} s…")
        elif kind == "result":
            self.finish(ev[1])
        elif kind == "tools_refresh":
            self.set_running(False)
            self.refresh_tools()
            ok = all(st.found for st in self.tools.values())
            self.set_status(
                "Herramientas instaladas." if ok else "Alguna herramienta no se pudo instalar: mira el Registro."
            )
            toast(
                self,
                "Herramientas listas." if ok else "Revisa la pestaña Registro.",
                STATUS_COLOR[Status.CLEAN if ok else Status.UNKNOWN],
            )
        elif kind == "cancelled":
            self.set_running(False)
            self.set_status("Análisis cancelado.")
            self.log_line("AVISO", "Análisis cancelado por el usuario.")
        elif kind == "fatal":
            self.set_running(False)
            self.set_status("Error.")
            self.log_line("ERROR", ev[1])
            messagebox.showerror("Error", ev[1], parent=self)

    def finish(self, res: TriageResult) -> None:
        self.set_running(False)
        self.progress.set(1)
        fmt = FORMATS[self.format_menu.get()]
        reports: list[Path] = []
        if fmt:
            reports = report.write_reports(res, self.reports_dir, fmt)
            if fmt not in ("json", "all"):  # el historial necesita siempre el JSON
                reports += report.write_reports(res, self.reports_dir, "json")
            for p in reports:
                self.log_line("INFO", f"Informe guardado: {p}")
        current_json = next((p for p in reports if p.suffix == ".json"), None)
        self.refresh_history()
        self.show_result(res, reports, current_json)

        c = res.counts()
        took = f" en {res.duration:.0f} s" if res.duration is not None else ""
        self.set_status(
            f"Terminado{took}: {c[Status.DETECTED]} detectados · {c[Status.UNKNOWN]} sospechosos · {c[Status.CLEAN]} limpios."
        )
        for e in res.errors:
            self.log_line("AVISO", e)
        if c[Status.DETECTED]:
            self.bell()
            toast(
                self,
                f"{c[Status.DETECTED]} elemento(s) detectados: revisa «Prioriza esto primero».",
                STATUS_COLOR[Status.DETECTED],
                4000,
            )

    def show_result(self, res: TriageResult, reports: list[Path], current_json: Path | None) -> None:
        self.result, self.findings, self.reports = res, res.findings, reports
        prev = history.previous_of(self.history_entries, current_json, res.started, res.dry_run)
        self.has_previous = prev is not None
        self.new_keys = {history.key_of(f) for f in self.findings if prev and history.key_of(f) not in prev.keys}
        mode = " · modo demostración" if res.dry_run else ""
        self.subtitle.configure(text=f"{res.host} · {res.started:%d/%m/%Y %H:%M}{mode}")
        self.filter_btn.set("Detectados" if res.counts()[Status.DETECTED] else "Todos")
        self.render_all()
        self.open_report_btn.configure(state="normal" if self.reports else "disabled")

    # ================================================================= renderizado
    def render_all(self) -> None:
        self.render_cards()
        self.render_dashboard()
        self.render_table()
        self.render_connections()

    def render_cards(self) -> None:
        res = self.result
        c = res.counts() if res else dict.fromkeys(Status, 0)
        self.cards["detected"].set(c[Status.DETECTED])
        self.cards["unknown"].set(c[Status.UNKNOWN])
        self.cards["clean"].set(c[Status.CLEAN])
        if res is None:
            self.cards["new"].set(0, hint="Desde el análisis anterior")
        elif self.has_previous:
            self.cards["new"].set(len(self.new_keys), hint="Desde el análisis anterior")
        else:
            self.cards["new"].set("—", hint="Primer análisis de este tipo")
        self.cards["whitelist"].set(res.whitelisted if res else 0)

    def render_dashboard(self) -> None:
        res = self.result
        c = res.counts() if res else dict.fromkeys(Status, 0)
        total = sum(c.values())
        self.donut.set(
            [
                ("Detectados", c[Status.DETECTED], STATUS_COLOR[Status.DETECTED]),
                ("Sospechosos", c[Status.UNKNOWN], STATUS_COLOR[Status.UNKNOWN]),
                ("Limpios", c[Status.CLEAN], STATUS_COLOR[Status.CLEAN]),
            ],
            str(total),
            "elementos",
        )
        top_score = max((f.score for f in self.findings), default=0)
        caption = (
            "sin análisis"
            if res is None
            else ("riesgo alto" if top_score >= 70 else "riesgo medio" if top_score >= 30 else "riesgo bajo")
        )
        self.gauge.set(top_score, caption, score_color(top_score))

        by_source: dict[str, list[Finding]] = {}
        for f in self.findings:
            if f.status is not Status.CLEAN:
                by_source.setdefault(SOURCE_LABEL.get(f.source, f.source), []).append(f)
        self.by_source.set(
            sorted(
                (
                    (label, len(fs), STATUS_COLOR[min((f.status for f in fs), key=lambda s: s.rank)], str(len(fs)))
                    for label, fs in by_source.items()
                ),
                key=lambda x: -x[1],
            )
        )
        self.attack_chart.set([(f"{t} {name}", n, CYAN, str(n)) for t, name, n in report.attack_summary(self.findings)])

        self.priority_tree.delete(*self.priority_tree.get_children())
        for i, f in enumerate(report.top_findings(self.findings), 1):
            self.priority_tree.insert(
                "",
                "end",
                iid=str(self.findings.index(f)),
                values=(i, f.score, SOURCE_LABEL.get(f.source, f.source), f.name, report.why(f, 3)),
                tags=(f.status.value,),
            )

    def visible_rows(self) -> list[tuple[int, Finding]]:
        wanted = FILTERS[self.filter_btn.get()]
        q = self.search.get().strip().lower()
        rows = []
        for i, f in enumerate(self.findings):
            if wanted and f.status is not wanted:
                continue
            if self.only_new.get() and history.key_of(f) not in self.new_keys:
                continue
            if q:
                hay = " ".join(
                    [
                        f.name,
                        f.path,
                        f.publisher,
                        f.signature,
                        f.sha256,
                        f.cmdline,
                        *f.attack,
                        *(s.title for s in f.signals),
                    ]
                ).lower()
                if q not in hay:
                    continue
            rows.append((i, f))
        key, reverse = self.sort_key
        sorters = {
            "estado": lambda r: (r[1].status.rank, -r[1].score, -r[1].raw_score),
            "score": lambda r: -r[1].score,
            "origen": lambda r: r[1].source,
            "nombre": lambda r: r[1].name.lower(),
            "ruta": lambda r: r[1].path.lower(),
            "why": lambda r: report.why(r[1]).lower(),
            "vt": lambda r: -((r[1].vt or {}).get("malicious", -1)),
            "red": lambda r: -len(r[1].connections),
            "nuevo": lambda r: history.key_of(r[1]) not in self.new_keys,
        }
        return sorted(rows, key=sorters[key], reverse=reverse)

    def sort_by(self, key: str) -> None:
        current, reverse = self.sort_key
        self.sort_key = (key, not reverse if current == key else False)
        self.render_table()

    def render_table(self) -> None:
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        rows = self.visible_rows()
        for n, (i, f) in enumerate(rows):
            st = f.status
            is_new = history.key_of(f) in self.new_keys
            tags = [st.value]
            if is_new:
                tags.append("new")
            elif n % 2:
                tags.append("odd")
            self.tree.insert(
                "",
                "end",
                iid=str(i),
                values=(
                    f"●  {st.value}",
                    f.score,
                    SOURCE_LABEL.get(f.source, f.source),
                    f.name,
                    f.path or "—",
                    report.why(f) or f.signature,
                    f.vt_summary,
                    len(f.connections) or "—",
                    "★ NUEVO" if is_new else "",
                ),
                tags=tuple(tags),
            )
        keep = [s for s in selected if self.tree.exists(s)]
        if keep:
            self.tree.selection_set(keep)
        else:
            self.set_detail(None)
        self.render_empty_state(bool(rows))
        with contextlib.suppress(
            AttributeError, KeyError
        ):  # contador en la pestaña (API interna de CustomTkinter, opcional)
            self.tabs._segmented_button._buttons_dict["Hallazgos"].configure(
                text=f"Hallazgos ({len(self.findings)})" if self.findings else "Hallazgos"
            )

    def render_empty_state(self, has_rows: bool) -> None:
        if has_rows:
            self.empty_label.place_forget()
            return
        if self.result is None:
            text = "Aún no hay resultados.\nPulsa «Analizar» (Ctrl+R) o prueba el modo demostración."
        elif not self.findings:
            text = "¡Sin hallazgos! No se encontró nada sospechoso con los módulos elegidos."
        else:
            text = "Ningún elemento coincide con el filtro o la búsqueda."
        self.empty_label.configure(text=text)
        self.empty_label.place(relx=0.5, rely=0.5, anchor="center")
        self.empty_label.lift()

    def render_connections(self) -> None:
        self.conn_tree.delete(*self.conn_tree.get_children())
        conns = report.unique_connections(self.findings)
        for n, (c, st) in enumerate(conns):
            self.conn_tree.insert(
                "",
                "end",
                values=(c.process, c.pid, c.protocol, c.state, c.local, c.remote, st.value),
                tags=(st.value, "odd") if n % 2 else (st.value,),
            )
        with contextlib.suppress(AttributeError, KeyError):
            self.tabs._segmented_button._buttons_dict["Conexiones"].configure(
                text=f"Conexiones ({len(conns)})" if conns else "Conexiones"
            )

    def selected_finding(self) -> Finding | None:
        sel = self.tree.selection()
        return self.findings[int(sel[0])] if sel else None

    def show_detail(self) -> None:
        self.set_detail(self.selected_finding())

    def set_detail(self, f: Finding | None) -> None:
        box = self.detail_box
        box.configure(state="normal")
        box.delete("1.0", "end")
        if f is None:
            box.insert("end", "Selecciona un elemento para ver por qué es sospechoso.", "muted")
        else:
            box.insert("end", f"{f.status.value} · score {f.score} — {f.name}\n", "title")
            box.insert(
                "end", f"{SOURCE_LABEL.get(f.source, f.source)} · {f.category or '—'} · {f.location or '—'}\n", "muted"
            )
            box.insert("end", f"Ruta: {f.path or '—'}\n")
            if f.cmdline:
                box.insert("end", f"Línea de comandos: {f.cmdline[:500]}\n")
            box.insert("end", f"Editor: {f.publisher} · Firma: {f.signature}\n")
            box.insert("end", f"SHA-256: {f.sha256 or 'no disponible'} · VirusTotal: {f.vt_summary}\n")
            for c in f.connections:
                box.insert("end", f"Conexión: {c.protocol} {c.local} → {c.remote} ({c.state}, PID {c.pid})\n")
            if f.unique_signals:
                box.insert("end", "\nPor qué:\n", "title")
                for s in f.unique_signals:
                    tag = "red" if s.weight >= 50 else ("pos" if s.weight > 0 else "neg")
                    attack = f"  [{s.attack}]" if s.attack else ""
                    box.insert("end", f"  {s.weight:+4d}  {s.title}{attack}\n", tag)
                    if s.evidence:
                        box.insert("end", f"         {s.evidence[:200]}\n", "muted")
        box.configure(state="disabled")
        state = "normal" if f else "disabled"
        for b in self.detail_buttons.values():
            b.configure(state=state)
        if f:
            if not f.sha256:
                for k in ("vt", "hash", "wl_hash"):
                    self.detail_buttons[k].configure(state="disabled")
            if not f.attack:
                self.detail_buttons["attack"].configure(state="disabled")
            if not self.windows or not f.path:
                self.detail_buttons["reveal"].configure(state="disabled")

    def jump_to_priority(self) -> None:
        sel = self.priority_tree.selection()
        if not sel:
            return
        self.filter_btn.set("Todos")
        self.search.delete(0, "end")
        self.only_new.set(False)
        self.render_table()
        self.tabs.set("Hallazgos")
        if self.tree.exists(sel[0]):
            self.tree.selection_set(sel[0])
            self.tree.see(sel[0])

    # ================================================================= historial
    def refresh_history(self) -> None:
        self.history_entries = history.list_reports(self.reports_dir)
        self.history_tree.delete(*self.history_tree.get_children())
        for n, e in enumerate(self.history_entries):
            s = e.summary
            tag = (
                Status.DETECTED.value
                if s.get("DETECTADO")
                else (Status.UNKNOWN.value if s.get("DESCONOCIDO") else Status.CLEAN.value)
            )
            self.history_tree.insert(
                "",
                "end",
                iid=str(n),
                values=(
                    f"{e.started:%d/%m/%Y %H:%M:%S}",
                    e.host,
                    "demostración" if e.dry_run else "real",
                    s.get("DETECTADO", 0),
                    s.get("DESCONOCIDO", 0),
                    s.get("LIMPIO", 0),
                    e.total,
                    e.max_score or "—",
                ),
                tags=(tag, "odd") if n % 2 else (tag,),
            )

    def selected_history(self) -> history.HistoryEntry | None:
        sel = self.history_tree.selection()
        return self.history_entries[int(sel[0])] if sel else None

    def load_history_entry(self) -> None:
        e = self.selected_history()
        if e is None:
            toast(self, "Selecciona un análisis del historial.")
            return
        try:
            res = report.load_json(e.path)
        except (OSError, ValueError, KeyError, TypeError) as err:
            messagebox.showerror("No se pudo cargar", f"{e.path.name}: {err}", parent=self)
            return
        siblings = [p for p in (e.sibling(".html"), e.sibling(".md"), e.path) if p]
        self.show_result(res, siblings, e.path)
        self.subtitle.configure(text=self.subtitle.cget("text") + " · cargado del historial")
        self.tabs.set("Panel")
        self.log_line("INFO", f"Análisis cargado: {e.path.name}")

    def open_history_report(self) -> None:
        e = self.selected_history()
        if e:
            open_path(e.sibling(".html") or e.sibling(".md") or e.path)

    # ================================================================= acciones
    def open_vt(self) -> None:
        f = self.selected_finding()
        if f and f.sha256:
            webbrowser.open(GUI_URL.format(f.sha256))

    def open_attack(self) -> None:
        f = self.selected_finding()
        if f and f.attack:
            webbrowser.open(attack_url(f.attack[0]))
            if len(f.attack) > 1:
                toast(self, "Técnicas: " + ", ".join(f"{t} {technique_name(t)}" for t in f.attack[:4]))

    def copy_hash(self) -> None:
        f = self.selected_finding()
        if f and f.sha256:
            self.to_clipboard(f.sha256)
            toast(self, "SHA-256 copiado.")

    def copy_path(self) -> None:
        f = self.selected_finding()
        if f and f.path:
            self.to_clipboard(f.path)
            toast(self, "Ruta copiada.")

    def reveal(self) -> None:
        f = self.selected_finding()
        if not f or not f.path:
            return
        path = Path(expand_win_vars(f.path.strip('"')))
        if not path.exists():
            messagebox.showinfo("No encontrado", f"El archivo ya no existe:\n{path}", parent=self)
            return
        subprocess.Popen(["explorer", f"/select,{path}"])

    def whitelist_selected(self, by_hash: bool) -> None:
        f = self.selected_finding()
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
            if by_hash:
                add_to_whitelist(file, sha256=value)
            else:
                add_to_whitelist(file, path=value)
        except (OSError, ValueError) as e:
            messagebox.showerror("No se pudo guardar", str(e), parent=self)
            return
        wl = Whitelist(hashes=[value]) if by_hash else Whitelist(paths=[value])
        for section, items in self.result.sections.items():
            kept, removed = wl.filter(items)
            self.result.sections[section] = kept
            self.result.whitelisted += removed
        self.findings = self.result.findings
        self.render_all()
        self.log_line("INFO", f"Añadido a whitelist.json: {value}")
        toast(self, "Añadido a la lista blanca.", STATUS_COLOR[Status.CLEAN])

    def selected_connection(self) -> tuple[str, ...] | None:
        sel = self.conn_tree.selection()
        return tuple(self.conn_tree.item(sel[0], "values")) if sel else None

    def _remote_ip(self) -> str | None:
        row = self.selected_connection()
        if not row:
            toast(self, "Selecciona una conexión.")
            return None
        return str(row[5]).rsplit(":", 1)[0].strip("[]")

    def lookup_ip(self) -> None:
        ip = self._remote_ip()
        if ip:
            webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{ip}")

    def copy_ip(self) -> None:
        ip = self._remote_ip()
        if ip:
            self.to_clipboard(ip)
            toast(self, f"IP {ip} copiada.")

    def popup_finding_menu(self, event: tk.Event) -> None:
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        f = self.findings[int(row)]
        menu = dark_menu(self)
        menu.add_command(label="Abrir en VirusTotal", command=self.open_vt, state="normal" if f.sha256 else "disabled")
        menu.add_command(
            label="Ver técnica ATT&CK", command=self.open_attack, state="normal" if f.attack else "disabled"
        )
        menu.add_separator()
        menu.add_command(label="Copiar SHA-256", command=self.copy_hash, state="normal" if f.sha256 else "disabled")
        menu.add_command(label="Copiar ruta", command=self.copy_path)
        menu.add_command(
            label="Copiar línea de comandos",
            command=lambda: self.to_clipboard(f.cmdline),
            state="normal" if f.cmdline else "disabled",
        )
        menu.add_command(
            label="Mostrar en el Explorador", command=self.reveal, state="normal" if self.windows else "disabled"
        )
        menu.add_separator()
        menu.add_command(label="Ignorar esta ruta", command=lambda: self.whitelist_selected(by_hash=False))
        menu.add_command(
            label="Ignorar este hash",
            command=lambda: self.whitelist_selected(by_hash=True),
            state="normal" if f.sha256 else "disabled",
        )
        menu.tk_popup(event.x_root, event.y_root)

    def popup_connection_menu(self, event: tk.Event) -> None:
        row = self.conn_tree.identify_row(event.y)
        if not row:
            return
        self.conn_tree.selection_set(row)
        menu = dark_menu(self)
        menu.add_command(label="Buscar IP en VirusTotal", command=self.lookup_ip)
        menu.add_command(label="Copiar IP remota", command=self.copy_ip)
        menu.tk_popup(event.x_root, event.y_root)

    # ================================================================= exportar
    def show_export_menu(self) -> None:
        menu = dark_menu(self)
        has = self.result is not None
        st = "normal" if has else "disabled"
        menu.add_command(label="CSV (vista actual)…   Ctrl+E", command=self.export_csv, state=st)
        menu.add_separator()
        for label, fmt in (("Informe HTML…", "html"), ("Informe Markdown…", "md"), ("JSON (esquema v2)…", "json")):
            menu.add_command(label=label, command=lambda f=fmt: self.export_report(f), state=st)
        x = self.export_btn.winfo_rootx()
        y = self.export_btn.winfo_rooty() + self.export_btn.winfo_height()
        menu.tk_popup(x, y)

    def export_csv(self, path: Path | None = None) -> Path | None:
        if self.result is None:
            toast(self, "Aún no hay resultados que exportar.")
            return None
        if path is None:
            chosen = filedialog.asksaveasfilename(
                parent=self,
                defaultextension=".csv",
                initialfile=f"{self.result.file_stem}.csv",
                filetypes=[("CSV", "*.csv")],
            )
            if not chosen:
                return None
            path = Path(chosen)
        cols = [
            "estado",
            "score",
            "origen",
            "nombre",
            "ruta",
            "linea_comandos",
            "editor",
            "firma",
            "sha256",
            "vt",
            "conexiones",
            "att&ck",
            "por_que",
            "nuevo",
        ]
        with path.open("w", newline="", encoding="utf-8-sig") as fh:  # utf-8-sig: Excel lo abre bien
            w = csv.writer(fh, delimiter=";")
            w.writerow(cols)
            for _, f in self.visible_rows():
                w.writerow(
                    [
                        f.status.value,
                        f.score,
                        f.source,
                        f.name,
                        f.path,
                        f.cmdline,
                        f.publisher,
                        f.signature,
                        f.sha256,
                        f.vt_summary,
                        " | ".join(c.remote for c in f.connections),
                        " ".join(f.attack),
                        " | ".join(s.title for s in f.unique_signals if s.weight > 0),
                        "sí" if history.key_of(f) in self.new_keys else "",
                    ]
                )
        self.log_line("INFO", f"CSV exportado: {path}")
        toast(self, f"Exportado: {path.name}")
        return path

    def export_report(self, fmt: str) -> None:
        if self.result is None:
            return
        ext = {"html": ".html", "md": ".md", "json": ".json"}[fmt]
        chosen = filedialog.asksaveasfilename(
            parent=self, defaultextension=ext, initialfile=f"{self.result.file_stem}{ext}"
        )
        if not chosen:
            return
        tmp_dir = Path(chosen).parent
        written = report.write_reports(self.result, tmp_dir, fmt)[0]
        target = Path(chosen)
        if written != target:
            written.replace(target)
        toast(self, f"Exportado: {target.name}")

    # ================================================================= configuración
    def edit_api_key(self) -> None:
        dlg = SecretDialog(self, os.environ.get("VT_API_KEY", ""))
        self.wait_window(dlg)
        if dlg.value is None:
            return
        self.env_file.parent.mkdir(parents=True, exist_ok=True)
        self.env_file.touch(exist_ok=True)
        set_key(str(self.env_file), "VT_API_KEY", dlg.value, quote_mode="never")
        os.environ["VT_API_KEY"] = dlg.value
        self.update_vt_status()
        self.log_line("INFO", f"Clave de VirusTotal guardada en {self.env_file}")
        toast(self, "Clave de VirusTotal guardada.", STATUS_COLOR[Status.CLEAN])

    def open_whitelist(self) -> None:
        file = self.config_dir / "whitelist.json"
        try:
            Whitelist.load(file)  # la crea con la plantilla si no existe
        except WhitelistError as e:
            messagebox.showwarning("whitelist.json", str(e), parent=self)
        open_path(file)

    def open_yara_dir(self) -> None:
        folder = self.config_dir / "yara"
        folder.mkdir(parents=True, exist_ok=True)
        open_path(folder)
        toast(self, "Copia aquí tus reglas .yar: se cargarán en el próximo análisis de contenido.")

    def open_reports_dir(self) -> None:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        open_path(self.reports_dir)

    def open_report(self) -> None:
        if self.reports:
            preferred = sorted(self.reports, key=lambda p: {".html": 0, ".md": 1}.get(p.suffix, 2))
            open_path(preferred[0])

    def relaunch_admin(self) -> None:
        if env_check.relaunch_as_admin(["--config-dir", str(self.config_dir)]):
            self.on_close()
        else:
            messagebox.showwarning("Elevación cancelada", "No se pudo reiniciar como administrador.", parent=self)

    def save_prefs(self) -> None:
        self.prefs["modules"] = {k: bool(v.get()) for k, v in self.module_vars.items()}
        self.prefs["event_days"] = int(self.days_menu.get())
        self.prefs["vt_limit"] = self.vt_limit.get().strip()
        self.prefs["format"] = self.format_menu.get()
        with contextlib.suppress(tk.TclError):
            self.prefs["geometry"] = self.geometry()
        settings.save(self.config_dir, self.prefs)

    # ================================================================= utilidades
    def set_running(self, running: bool) -> None:
        self.run_btn.configure(
            state="disabled" if running else "normal", text="Analizando…" if running else "▶  Analizar"
        )
        self.cancel_btn.configure(state="normal" if running else "disabled")
        if running:
            self.started_at = time.monotonic()
            self.elapsed_label.configure(text="0 s")
            self.open_report_btn.configure(state="disabled")
            self.progress.set(0)
        else:
            self.indeterminate(False)
            if not self.reports:
                self.open_report_btn.configure(state="disabled")

    def indeterminate(self, on: bool) -> None:
        if on:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate")

    def set_status(self, text: str) -> None:
        self.status_label.configure(text=text if len(text) < 90 else text[:87] + "…")

    def log_line(self, level: str, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{datetime.now():%H:%M:%S}  {level:<5}  {text}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def clear_log(self) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def focus_search(self) -> None:
        self.tabs.set("Hallazgos")
        self.search.focus_set()

    def to_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    def on_close(self) -> None:
        self.cancel_flag.set()
        self.save_prefs()
        self.destroy()
