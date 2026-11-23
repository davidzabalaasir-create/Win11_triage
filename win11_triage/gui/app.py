"""Ventana principal de win11-triage.

Layout: nav rail (izquierda) · barra superior (título, búsqueda, acción principal) · página ·
barra de estado (entorno + progreso) · registro plegable.

El análisis corre en un hilo aparte (TriageEngine); la interfaz solo se actualiza desde el
hilo principal, leyendo una cola de eventos cada 100 ms.
"""

from __future__ import annotations

import contextlib
import copy
import logging
import os
import platform
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
import requests
from dotenv import load_dotenv, set_key

from .. import __version__, alerts, collectors_live, env_check, history, i18n, playbook, report, scheduler
from .. import agent as agent_mod
from ..engine import PLACEHOLDER_KEY, Reporter, TriageEngine, TriageOptions
from ..enrich import pe_static, yara_scan
from ..models import Cancelled, Finding, Status
from ..remote import RemoteError, valid_host
from ..report import TriageResult
from ..review import PENDING, STATE_KEYS, STATE_TOKEN, STATES, ReviewStore
from ..rules.attack import attack_url, technique_name
from ..utils import expand_win_vars
from ..virustotal import GUI_URL
from ..whitelist import Whitelist, WhitelistError, add_to_whitelist, remove_from_whitelist
from . import settings
from .dialogs import PRESETS, CompareDialog, NewScanDialog
from .theme import (
    CONTROL_H,
    ICON_ICO,
    ICON_SMALL,
    RADIUS,
    ROW_H,
    SPACE,
    STATUS_LABEL,
    STATUS_TOKEN,
    T,
    c,
    elide_middle,
    font,
    glyph,
    icon_font,
    mono,
    score_token,
    status_color,
    tk_font,
)
from .widgets import (
    AboutDialog,
    Badge,
    BarChart,
    DonutChart,
    FilterChips,
    NavRail,
    ScoreGauge,
    SecretDialog,
    StatCard,
    Tooltip,
    card,
    flash_button,
    ghost_button,
    icon_button,
    load_logo,
    make_dot,
    option_style,
    primary_button,
    secondary_button,
    segmented_style,
    themed_menu,
    toast,
)

log = logging.getLogger(__name__)

FILTERS = {"Todos": None, "Detectados": Status.DETECTED, "Sospechosos": Status.UNKNOWN, "Limpios": Status.CLEAN}
FORMATS = {
    "HTML": "html",
    "PDF ejecutivo": "pdf",
    "Markdown": "md",
    "JSON": "json",
    "Todos (HTML+MD+JSON+PDF)": "all",
    "No guardar": None,
}
SOURCE_LABEL = report.SOURCE_LABEL
PAGES = (
    ("home", "Inicio", "home"),
    ("findings", "Hallazgos", "findings"),
    ("network", "Red", "network"),
    ("processes", "Procesos", "tree"),
    ("assistant", "Asistente", "chat"),
    ("history", "Historial", "history"),
    ("settings", "Ajustes", "settings"),
)
PAGE_SUBTITLE = {
    "home": "Resumen del último análisis",
    "findings": "Todo lo encontrado, con el porqué de cada elemento",
    "network": "Conexiones externas de los procesos señalados",
    "processes": "Árbol padre → hijo; las ramas con procesos señalados aparecen desplegadas",
    "assistant": "Pregunta en lenguaje natural sobre el análisis",
    "history": "Análisis anteriores guardados en la carpeta de informes",
    "settings": "Claves, listas blancas, herramientas y apariencia",
}
APPEARANCE = {"Sistema": "system", "Claro": "light", "Oscuro": "dark"}
SCHEDULES = {"Desactivado": "off", "Diario": "daily", "Semanal": "weekly"}
INTEL_KEYS = (
    ("AbuseIPDB", "ABUSEIPDB_API_KEY", "https://www.abuseipdb.com/account/api"),
    ("MalwareBazaar", "MALWAREBAZAAR_API_KEY", "https://auth.abuse.ch/"),
)


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
        self.prefs = settings.load(config_dir)
        i18n.set_language(self.prefs.get("language", "es"))
        ctk.set_appearance_mode(APPEARANCE.get(self.prefs.get("appearance", "Oscuro"), "dark"))
        super().__init__()
        self.config_dir = config_dir
        self.env_file = config_dir / ".env"
        self.reports_dir = config_dir / "reportes"
        load_dotenv(self.env_file, override=True)

        self.events: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self.cancel_flag = threading.Event()
        self.worker: threading.Thread | None = None
        self.result: TriageResult | None = None
        self.previous: history.HistoryEntry | None = None
        self.findings: list[Finding] = []
        self.new_keys: set[str] = set()
        self.has_previous = False
        self.reports: list[Path] = []
        self.history_entries: list[history.HistoryEntry] = []
        self.sort_key = ("estado", False)
        self.started_at = 0.0
        self.page = "home"
        self.selected: Finding | None = None
        self._detail_lines: list[str] = []
        self._loaded_suffix = ""
        self.reviews = ReviewStore(config_dir)
        self.tools = env_check.check_all()
        self.windows = env_check.is_windows()
        self.admin = env_check.is_admin()

        # Configuración del próximo análisis (la edita el diálogo «Nuevo análisis»)
        self.module_vars = {k: ctk.BooleanVar(value=v) for k, v in self.prefs["modules"].items()}
        self.var_dry = ctk.BooleanVar(value=not self.windows)
        self.var_days = ctk.StringVar(value=str(self.prefs.get("event_days", 7)))
        self.var_vt_limit = ctk.StringVar(value=str(self.prefs.get("vt_limit") or ""))
        fmt = self.prefs.get("format")
        self.var_format = ctk.StringVar(value=fmt if fmt in FORMATS else "HTML")
        self.var_remote = ctk.StringVar(value="")
        self.var_notify = ctk.BooleanVar(value=bool(self.prefs.get("notify", True)))
        self.var_alert_new = ctk.BooleanVar(value=bool(self.prefs.get("alert_new", True)))

        self.title(f"win11-triage {__version__}")
        self.geometry(self.prefs.get("geometry") or "1440x900")
        self.minsize(1200, 760)
        self.configure(fg_color=T("bg"))
        self._ui_icon()
        self._ui_style()
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._ui_nav()
        self._ui_main()
        self._ui_statusbar()
        self._ui_shortcuts()

        self.refresh_tools()
        self.refresh_history()
        self.render_all()
        self.show_page("home")
        self.set_running(False)
        self.log_line("INFO", f"Carpeta de configuración: {self.config_dir}")
        if not self.windows:
            self.log_line("AVISO", "Este sistema no es Windows: solo está disponible el modo demostración.")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.update_agent_status()
        i18n.translate_tree(self)
        self.after(100, self.poll_events)

    # ================================================================= estructura
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
        """Estilo de ttk (tablas) y puntos de estado; se recalcula al cambiar de tema."""
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Triage.Treeview",
            background=c("surface"),
            fieldbackground=c("surface"),
            foreground=c("text"),
            rowheight=ROW_H,
            borderwidth=0,
            font=tk_font("body"),
        )
        style.map("Triage.Treeview", background=[("selected", c("accent_soft"))], foreground=[("selected", c("text"))])
        style.configure(
            "Triage.Treeview.Heading",
            background=c("surface2"),
            foreground=c("text2"),
            relief="flat",
            font=tk_font("caption_bold"),
            padding=(SPACE["s"], SPACE["s"]),
        )
        style.map("Triage.Treeview.Heading", background=[("active", c("border"))])
        style.layout("Triage.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        self.dots = {st: make_dot(self, status_color(st)) for st in Status}

    def _ui_nav(self) -> None:
        self.nav = NavRail(self, list(PAGES), self.show_page)
        self.nav.grid(row=0, column=0, rowspan=2, sticky="nsw")
        brand = self.nav.top
        logo = load_logo(36)
        if logo:
            ctk.CTkLabel(brand, text="", image=logo).pack(side="left")
        names = ctk.CTkFrame(brand, fg_color="transparent")
        names.pack(side="left", padx=SPACE["s"])
        ctk.CTkLabel(names, text="win11-triage", font=font("subtitle")).pack(anchor="w")
        ctk.CTkLabel(names, text=f"v{__version__}", font=font("caption"), text_color=T("text2")).pack(anchor="w")
        ghost_button(self.nav.bottom, "Acerca de", lambda: AboutDialog(self), text_color=T("text2"), anchor="w").pack(
            fill="x"
        )

    def _ui_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color=T("bg"), corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        # ---- barra superior
        top = ctk.CTkFrame(main, fg_color="transparent", height=56)
        top.grid(row=0, column=0, sticky="ew", padx=SPACE["xl"], pady=(SPACE["l"], 0))
        titles = ctk.CTkFrame(top, fg_color="transparent")
        titles.pack(side="left")
        self.page_title = ctk.CTkLabel(titles, text="Inicio", font=font("title"))
        self.page_title.pack(anchor="w")
        self.subtitle = ctk.CTkLabel(titles, text="", font=font("caption"), text_color=T("text2"))
        self.subtitle.pack(anchor="w")

        self.run_btn = primary_button(top, "Analizar", self.open_new_scan, icon="play", width=150)
        self.run_btn.pack(side="right")
        Tooltip(self.run_btn, "Nuevo análisis (Ctrl+N) · Repetir el último: Ctrl+R")
        self.export_btn = secondary_button(top, "Exportar", None, icon="export", width=120)
        self.export_btn.configure(command=self.show_export_menu)
        self.export_btn.pack(side="right", padx=SPACE["s"])
        self.open_report_btn = icon_button(top, "open", self.open_report, "Abrir informe (Ctrl+O)", size=CONTROL_H)
        self.open_report_btn.pack(side="right")
        self.search = ctk.CTkEntry(
            top,
            width=320,
            height=CONTROL_H,
            corner_radius=RADIUS["control"],
            placeholder_text="Buscar nombre, ruta, hash o técnica   (Ctrl+F)",
            border_color=T("border"),
            fg_color=T("surface"),
            font=font("body"),
        )
        self.search.pack(side="right", padx=SPACE["l"])
        self.search.bind("<KeyRelease>", lambda _e: self._on_search())

        # ---- progreso (fino, bajo la barra superior)
        self.progress = ctk.CTkProgressBar(
            main, height=3, corner_radius=0, progress_color=T("accent"), fg_color=T("bg")
        )
        self.progress.grid(row=1, column=0, sticky="ew", pady=(SPACE["m"], 0))
        self.progress.set(0)

        # ---- páginas
        self.page_host = ctk.CTkFrame(main, fg_color="transparent")
        self.page_host.grid(row=2, column=0, sticky="nsew", padx=SPACE["xl"], pady=SPACE["l"])
        self.page_host.grid_columnconfigure(0, weight=1)
        self.page_host.grid_rowconfigure(0, weight=1)
        self.pages: dict[str, ctk.CTkFrame] = {}
        for key, builder in (
            ("home", self._page_home),
            ("findings", self._page_findings),
            ("network", self._page_network),
            ("processes", self._page_processes),
            ("assistant", self._page_assistant),
            ("history", self._page_history),
            ("settings", self._page_settings),
        ):
            frame = ctk.CTkFrame(self.page_host, fg_color=T("bg"))
            frame.grid(row=0, column=0, sticky="nsew")
            builder(frame)
            self.pages[key] = frame

        # ---- registro plegable
        self.log_panel = card(main)
        self.log_panel.grid_columnconfigure(0, weight=1)
        head = ctk.CTkFrame(self.log_panel, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=SPACE["l"], pady=(SPACE["s"], 0))
        ctk.CTkLabel(head, text="Registro", font=font("subtitle")).pack(side="left")
        icon_button(head, "close", self.toggle_log, "Cerrar (Ctrl+L)").pack(side="right")
        icon_button(head, "copy", lambda: self.to_clipboard(self.log_box.get("1.0", "end")), "Copiar registro").pack(
            side="right"
        )
        self.log_box = ctk.CTkTextbox(self.log_panel, height=160, fg_color=T("surface"), font=mono(12), wrap="none")
        self.log_box.grid(row=1, column=0, sticky="ew", padx=SPACE["s"], pady=SPACE["s"])
        self.log_box.configure(state="disabled")
        self.log_visible = False

    def _ui_statusbar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=T("surface"), corner_radius=0, height=30)
        bar.grid(row=1, column=1, sticky="ew")
        self.env_chips = ctk.CTkFrame(bar, fg_color="transparent")
        self.env_chips.pack(side="left", padx=(SPACE["l"], SPACE["s"]))
        self.status_label = ctk.CTkLabel(bar, text="Listo.", font=font("caption"), text_color=T("text2"), anchor="w")
        self.status_label.pack(side="left", padx=SPACE["s"], fill="x", expand=True)
        self.log_btn = ghost_button(
            bar, f"{glyph('log')}  Registro", self.toggle_log, height=24, text_color=T("text2"), width=100
        )
        self.log_btn.pack(side="right", padx=SPACE["s"])
        self.elapsed_label = ctk.CTkLabel(bar, text="", font=font("caption"), text_color=T("text2"), width=60)
        self.elapsed_label.pack(side="right")

    def _ui_shortcuts(self) -> None:
        self.bind("<Control-r>", lambda _e: self.start())
        self.bind("<Control-n>", lambda _e: self.open_new_scan())
        self.bind("<Escape>", lambda _e: self.cancel())
        self.bind("<F5>", lambda _e: self.refresh_tools())
        self.bind("<Control-f>", lambda _e: self.focus_search())
        self.bind("<Control-e>", lambda _e: self.export_csv())
        self.bind("<Control-o>", lambda _e: self.open_report())
        self.bind("<Control-l>", lambda _e: self.toggle_log())
        for i, (key, _, _) in enumerate(PAGES, 1):
            self.bind(f"<Control-Key-{i}>", lambda _e, k=key: self.show_page(k))

    def _tree(
        self,
        parent: Any,
        columns: tuple[tuple[str, str, int, bool], ...],
        *,
        sortable: bool = False,
        height: int | None = None,
    ) -> ttk.Treeview:
        """Tabla con estilo y columna de estado (punto de color + texto). columns: (clave, título, ancho, estira)."""
        frame = ctk.CTkFrame(
            parent, fg_color=T("surface"), corner_radius=RADIUS["card"], border_width=1, border_color=T("border")
        )
        frame.pack(fill="both", expand=True)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        kw: dict[str, Any] = {"height": height} if height else {}
        tree = ttk.Treeview(
            frame, columns=[col[0] for col in columns], show="tree headings", style="Triage.Treeview", **kw
        )
        tree.heading("#0", text="Estado", anchor="w", command=(lambda: self.sort_by("estado")) if sortable else "")
        tree.column("#0", width=124, minwidth=110, stretch=False, anchor="w")
        for key, title, width, stretch in columns:
            cmd = (lambda k=key: self.sort_by(k)) if sortable else ""
            anchor = "e" if key in ("score", "red", "det", "unk", "ok", "total", "max", "pid") else "w"
            tree.heading(key, text=title, anchor=anchor, command=cmd)
            tree.column(key, width=width, minwidth=40, anchor=anchor, stretch=stretch)
        yscroll = ctk.CTkScrollbar(frame, command=tree.yview, button_color=T("border"))
        tree.configure(yscrollcommand=yscroll.set)
        tree.grid(row=0, column=0, sticky="nsew", padx=(SPACE["xs"], 0), pady=SPACE["xs"])
        yscroll.grid(row=0, column=1, sticky="ns", pady=SPACE["s"])
        return tree

    # ================================================================= páginas
    def _page_home(self, page: ctk.CTkFrame) -> None:
        page.grid_columnconfigure((0, 1, 2), weight=1, uniform="home")
        page.grid_rowconfigure((1, 2), weight=1)
        kpis = ctk.CTkFrame(page, fg_color="transparent")
        kpis.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, SPACE["l"]))
        self.cards: dict[str, StatCard] = {}
        for i, (key, title, hint, token, icon) in enumerate(
            (
                ("detected", "Detectados", "VirusTotal o score ≥ 70", "danger", "alert"),
                ("unknown", "Sospechosos", "Revisar manualmente", "warning", "warning"),
                ("clean", "Limpios", "Firma válida o VT limpio", "success", "check"),
                ("new", "Nuevos", "Desde el análisis anterior", "info", "info"),
            )
        ):
            kpis.grid_columnconfigure(i, weight=1, uniform="kpi")
            sc = StatCard(kpis, title, hint, token, icon)
            sc.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else SPACE["l"], 0))
            self.cards[key] = sc

        prio = card(page, "Prioriza esto primero")
        prio.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=(0, SPACE["l"]), pady=(0, SPACE["l"]))
        holder = ctk.CTkFrame(prio, fg_color="transparent")
        holder.pack(fill="both", expand=True, padx=SPACE["m"], pady=SPACE["m"])
        self.priority_tree = self._tree(
            holder,
            (
                ("score", "Score", 64, False),
                ("origen", "Origen", 110, False),
                ("nombre", "Nombre", 200, False),
                ("why", "Por qué", 360, True),
            ),
            height=5,
        )
        self.priority_tree.bind("<Double-1>", lambda _e: self.jump_to_priority())
        self.priority_tree.bind("<Return>", lambda _e: self.jump_to_priority())

        g = card(page, "Puntuación máxima")
        g.grid(row=1, column=2, sticky="nsew", pady=(0, SPACE["l"]))
        self.gauge = ScoreGauge(g, height=180)
        self.gauge.pack(fill="both", expand=True, padx=SPACE["m"], pady=SPACE["m"])

        a = card(page, "Técnicas MITRE ATT&CK")
        a.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=(0, SPACE["l"]))
        self.attack_chart = BarChart(a, height=180, limit=6, empty="Sin técnicas observadas")
        self.attack_chart.pack(fill="both", expand=True, padx=SPACE["m"], pady=SPACE["m"])

        d = card(page, "Distribución")
        d.grid(row=2, column=2, sticky="nsew")
        self.donut = DonutChart(d, height=180)
        self.donut.pack(fill="both", expand=True, padx=SPACE["m"], pady=SPACE["m"])

        # Estado vacío: cubre la página hasta el primer análisis
        self.home_empty = card(page)
        inner = ctk.CTkFrame(self.home_empty, fg_color="transparent")
        inner.place(relx=0.5, rely=0.45, anchor="center")
        logo = load_logo(72)
        if logo:
            ctk.CTkLabel(inner, text="", image=logo).pack(pady=(0, SPACE["l"]))
        ctk.CTkLabel(inner, text="Aún no hay ningún análisis", font=font("title")).pack()
        ctk.CTkLabel(
            inner,
            text="Revisa la persistencia, los procesos y la red de este equipo en unos minutos.",
            font=font("body"),
            text_color=T("text2"),
        ).pack(pady=(SPACE["xs"], SPACE["l"]))
        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack()
        primary_button(row, "Nuevo análisis", self.open_new_scan, icon="play", width=170).pack(
            side="left", padx=SPACE["xs"]
        )
        secondary_button(row, "Probar con datos de ejemplo", self.start_demo, width=220).pack(
            side="left", padx=SPACE["xs"]
        )

    def _page_findings(self, page: ctk.CTkFrame) -> None:
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, SPACE["m"]))
        self.filter_btn = FilterChips(bar, list(FILTERS), command=lambda _v: self.render_table())
        self.filter_btn.pack(side="left")
        self.review_filter = ctk.StringVar(value="Cualquier revisión")
        ctk.CTkOptionMenu(
            bar,
            values=["Cualquier revisión", *STATES],
            variable=self.review_filter,
            command=lambda _v: self.render_table(),
            width=190,
            **{**option_style(), "height": 30},
        ).pack(side="left", padx=(SPACE["s"], 0))
        self.review_progress = ctk.CTkLabel(bar, text="", font=font("caption"), text_color=T("text2"))
        self.review_progress.pack(side="left", padx=SPACE["l"])
        self.only_new = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(
            bar,
            text="Solo nuevos",
            variable=self.only_new,
            command=self.render_table,
            font=font("body"),
            progress_color=T("accent"),
        ).pack(side="right")

        holder = ctk.CTkFrame(page, fg_color="transparent")
        holder.grid(row=1, column=0, sticky="nsew")
        self.tree = self._tree(
            holder,
            (
                ("score", "Score", 56, False),
                ("origen", "Origen", 106, False),
                ("nombre", "Nombre", 136, False),
                ("ruta", "Ruta", 150, True),
                ("why", "Por qué", 160, True),
                ("vt", "VT", 96, False),
                ("rev", "Revisión", 126, False),
            ),
            sortable=True,
        )
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_detail())
        self.tree.bind("<Double-1>", lambda _e: self.open_vt())
        self.tree.bind("<Button-3>", self.popup_finding_menu)
        for key, state in STATE_KEYS.items():  # p / r / f / c: revisar sin ratón
            self.tree.bind(f"<KeyPress-{key}>", lambda _e, st=state: self.set_review(st))
        self.empty_label = ctk.CTkLabel(
            holder, text="", font=font("body"), text_color=T("text2"), fg_color=T("surface")
        )

        # Panel de detalle lateral
        self.detail = ctk.CTkFrame(
            page,
            width=380,
            fg_color=T("surface"),
            corner_radius=RADIUS["card"],
            border_width=1,
            border_color=T("border"),
        )
        self.detail.grid(row=1, column=1, sticky="nsew", padx=(SPACE["l"], 0))
        self.detail.grid_propagate(False)
        self.detail.grid_columnconfigure(0, weight=1)
        self.detail.grid_rowconfigure(0, weight=1)
        self.detail_body = ctk.CTkScrollableFrame(self.detail, fg_color="transparent")
        self.detail_body.grid(row=0, column=0, sticky="nsew", padx=SPACE["xs"], pady=SPACE["xs"])
        foot = ctk.CTkFrame(self.detail, fg_color="transparent")
        foot.grid(row=1, column=0, sticky="ew", padx=SPACE["l"], pady=SPACE["l"])
        self.vt_btn = primary_button(foot, "Ver en VirusTotal", self.open_vt, icon="open")
        self.vt_btn.pack(fill="x")
        row = ctk.CTkFrame(foot, fg_color="transparent")
        row.pack(fill="x", pady=(SPACE["s"], 0))
        self.copy_hash_btn = secondary_button(row, "Copiar SHA-256", self.copy_hash, icon="copy")
        self.copy_hash_btn.pack(side="left", fill="x", expand=True)
        self.more_btn = secondary_button(row, glyph("more"), None, width=CONTROL_H)
        self.more_btn.configure(command=lambda: self.popup_finding_menu(None))
        self.more_btn.pack(side="left", padx=(SPACE["s"], 0))
        Tooltip(self.more_btn, "Más acciones")
        self.set_detail(None)

    def _page_network(self, page: ctk.CTkFrame) -> None:
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.pack(fill="x", pady=(0, SPACE["m"]))
        secondary_button(bar, "Buscar IP en VirusTotal", self.lookup_ip, icon="open").pack(side="left")
        self.copy_ip_btn = secondary_button(bar, "Copiar IP", self.copy_ip, icon="copy")
        self.copy_ip_btn.pack(side="left", padx=SPACE["s"])
        self.conn_tree = self._tree(
            page,
            (
                ("proceso", "Proceso", 170, False),
                ("pid", "PID", 70, False),
                ("proto", "Proto", 60, False),
                ("estado", "Estado", 120, False),
                ("local", "Local", 200, False),
                ("remoto", "Remoto", 240, True),
            ),
        )
        self.conn_tree.bind("<Button-3>", self.popup_connection_menu)

    def _page_processes(self, page: ctk.CTkFrame) -> None:
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.pack(fill="x", pady=(0, SPACE["m"]))
        self.only_flagged_tree = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(
            bar,
            text="Solo ramas con procesos señalados",
            variable=self.only_flagged_tree,
            command=self.render_process_tree,
            font=font("body"),
            progress_color=T("accent"),
        ).pack(side="left")
        self.proc_info = ctk.CTkLabel(bar, text="", font=font("caption"), text_color=T("text2"))
        self.proc_info.pack(side="right")
        frame = ctk.CTkFrame(
            page, fg_color=T("surface"), corner_radius=RADIUS["card"], border_width=1, border_color=T("border")
        )
        frame.pack(fill="both", expand=True)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        self.proc_tree = ttk.Treeview(
            frame, columns=("pid", "score", "ruta", "cmd"), show="tree headings", style="Triage.Treeview"
        )
        self.proc_tree.heading("#0", text="Proceso", anchor="w")
        self.proc_tree.column("#0", width=280, minwidth=200, stretch=False)
        for key, title, width, stretch, anchor in (
            ("pid", "PID", 70, False, "e"),
            ("score", "Score", 60, False, "e"),
            ("ruta", "Ruta", 300, True, "w"),
            ("cmd", "Línea de comandos", 360, True, "w"),
        ):
            self.proc_tree.heading(key, text=title, anchor=anchor)
            self.proc_tree.column(key, width=width, minwidth=40, stretch=stretch, anchor=anchor)
        ys = ctk.CTkScrollbar(frame, command=self.proc_tree.yview, button_color=T("border"))
        self.proc_tree.configure(yscrollcommand=ys.set)
        self.proc_tree.grid(row=0, column=0, sticky="nsew", padx=(SPACE["xs"], 0), pady=SPACE["xs"])
        ys.grid(row=0, column=1, sticky="ns", pady=SPACE["s"])
        self.proc_tree.bind("<Double-1>", lambda _e: self.jump_to_process())
        self.proc_empty = ctk.CTkLabel(frame, text="", font=font("body"), text_color=T("text2"), fg_color=T("surface"))

    def _page_assistant(self, page: ctk.CTkFrame) -> None:
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.pack(fill="x", pady=(0, SPACE["m"]))
        self.agent_status = Badge(bar, "", "warning")
        self.agent_status.pack(side="left")
        ghost_button(bar, "Nueva conversación", self.reset_agent, width=170).pack(side="right")
        secondary_button(bar, "Configurar…", lambda: self.show_page("settings"), icon="key", width=150).pack(
            side="right", padx=SPACE["s"]
        )
        self.chat_box = ctk.CTkTextbox(
            page,
            fg_color=T("surface"),
            border_width=1,
            border_color=T("border"),
            corner_radius=RADIUS["card"],
            font=font("body"),
            wrap="word",
        )
        self.chat_box.pack(fill="both", expand=True)
        self.chat_box.tag_config("user", foreground=c("accent"))
        self.chat_box.tag_config("meta", foreground=c("text2"))
        self.chat_box.configure(state="disabled")
        chips = ctk.CTkFrame(page, fg_color="transparent")
        chips.pack(fill="x", pady=(SPACE["s"], 0))
        for q in agent_mod.SUGGESTIONS:
            ctk.CTkButton(
                chips,
                text=q,
                height=28,
                corner_radius=14,
                border_width=1,
                border_color=T("border"),
                fg_color="transparent",
                hover_color=T("surface2"),
                text_color=T("text2"),
                font=font("caption"),
                command=lambda q=q: self.ask_agent(i18n.t(q)),
            ).pack(side="left", padx=(0, SPACE["s"]))
        row = ctk.CTkFrame(page, fg_color="transparent")
        row.pack(fill="x", pady=(SPACE["s"], 0))
        self.chat_entry = ctk.CTkEntry(
            row,
            height=CONTROL_H,
            corner_radius=RADIUS["control"],
            fg_color=T("surface2"),
            border_color=T("border"),
            font=font("body"),
            placeholder_text="Escribe tu pregunta y pulsa Intro",
        )
        self.chat_entry.pack(side="left", fill="x", expand=True)
        self.chat_entry.bind("<Return>", lambda _e: self.ask_agent())
        self.chat_send = primary_button(row, "Enviar", self.ask_agent, icon="play", width=120)
        self.chat_send.pack(side="left", padx=(SPACE["s"], 0))
        ctk.CTkLabel(
            page,
            text="Se envía un resumen del análisis sin tu usuario ni el nombre del equipo. "
            "El asistente solo consulta datos: no cambia nada.",
            font=font("caption"),
            text_color=T("text2"),
        ).pack(anchor="w", pady=(SPACE["xs"], 0))
        self.agent: agent_mod.Agent | None = None
        self.chat_write(
            i18n.t("Hola. Haz un análisis (o carga uno del historial) y pregúntame lo que quieras sobre él."), "meta"
        )

    def update_agent_status(self) -> None:
        cfg = agent_mod.AgentConfig.from_env()
        if cfg.ready:
            self.agent_status.set(f"{cfg.provider} · {cfg.model}", "success")
        else:
            self.agent_status.set(i18n.t("Sin clave de Groq"), "warning")

    def chat_write(self, text: str, tag: str = "") -> None:
        self.chat_box.configure(state="normal")
        self.chat_box.insert("end", text + "\n\n", tag)
        self.chat_box.configure(state="disabled")
        self.chat_box.see("end")

    def reset_agent(self) -> None:
        if self.agent is not None:
            self.agent.reset()
        self.chat_box.configure(state="normal")
        self.chat_box.delete("1.0", "end")
        self.chat_box.configure(state="disabled")
        self.chat_write(i18n.t("Conversación nueva."), "meta")

    def ask_agent(self, question: str | None = None) -> None:
        q = (question or self.chat_entry.get()).strip()
        if not q or str(self.chat_send.cget("state")) == "disabled":
            return
        if self.result is None:
            toast(self, "Primero haz o carga un análisis.", "warning")
            return
        load_dotenv(self.env_file, override=True)
        if self.agent is None or self.agent.res is not self.result:
            self.agent = agent_mod.Agent(self.result)
        self.chat_entry.delete(0, "end")
        self.chat_write(f"› {q}", "user")
        self.chat_send.configure(state="disabled")
        self.set_status("Pensando…")
        self.indeterminate(True)
        agent = self.agent

        def work() -> None:
            try:
                answer = agent.ask(q, on_tool=lambda n: self.events.put(("agent_tool", n)))
                self.events.put(("agent_reply", answer))
            except agent_mod.AgentError as e:
                self.events.put(("agent_reply", f"⚠ {e}"))
            except Exception as e:  # nunca debe tumbar la interfaz
                log.exception("Error del asistente")
                self.events.put(("agent_reply", f"⚠ {type(e).__name__}: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def render_process_tree(self) -> None:
        tree = self.proc_tree
        tree.delete(*tree.get_children())
        procs = self.result.processes if self.result else []
        if not procs:
            self.proc_info.configure(text="")
            self.proc_empty.configure(text="Activa «Procesos en ejecución» en el análisis para ver el árbol.")
            self.proc_empty.place(relx=0.5, rely=0.5, anchor="center")
            return
        self.proc_empty.place_forget()
        by_pid = {p["pid"]: p for p in procs}
        children: dict[int, list[dict]] = {}
        for p in procs:
            children.setdefault(p["ppid"] if p["ppid"] in by_pid and p["ppid"] != p["pid"] else -1, []).append(p)
        keep: set[int] = set()
        for p in procs:  # el proceso señalado y todos sus antecesores
            if p.get("flagged"):
                cur, seen = p, set()
                while cur and cur["pid"] not in seen:
                    seen.add(cur["pid"])
                    keep.add(cur["pid"])
                    cur = by_pid.get(cur["ppid"])
        only = self.only_flagged_tree.get()

        def add(parent_iid: str, p: dict) -> None:
            if only and p["pid"] not in keep:
                return
            flagged = p.get("flagged")
            st = Status.DETECTED if p.get("score", 0) >= 70 else (Status.UNKNOWN if flagged else None)
            iid = f"p{p['pid']}"
            tree.insert(
                parent_iid,
                "end",
                iid=iid,
                text=f"  {p['name']}",
                image=self.dots[st] if st else "",
                values=(
                    p["pid"],
                    p.get("score") or "",
                    elide_middle(p.get("exe") or "—", 60),
                    p.get("cmdline", "")[:200],
                ),
                open=p["pid"] in keep,
            )
            for ch in sorted(children.get(p["pid"], []), key=lambda x: x["name"]):
                add(iid, ch)

        for root in sorted(children.get(-1, []), key=lambda x: x["name"]):
            add("", root)
        flagged_n = sum(1 for p in procs if p.get("flagged"))
        self.proc_info.configure(
            text=f"{len(procs)} procesos · {flagged_n} señalados · doble clic para ver el hallazgo"
        )

    def jump_to_process(self) -> None:
        sel = self.proc_tree.selection()
        if not sel:
            return
        pid = int(sel[0][1:])
        for i, f in enumerate(self.findings):
            if f.pid == pid:
                self.filter_btn.set("Todos")
                self.search.delete(0, "end")
                self.render_table()
                self.show_page("findings")
                if self.tree.exists(str(i)):
                    self.tree.selection_set(str(i))
                    self.tree.see(str(i))
                return
        toast(self, "Este proceso no tiene hallazgos: solo forma parte de la cadena.")

    def _page_history(self, page: ctk.CTkFrame) -> None:
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.pack(fill="x", pady=(0, SPACE["m"]))
        primary_button(bar, "Cargar análisis", self.load_history_entry, icon="history").pack(side="left")
        secondary_button(bar, "Comparar con el actual", self.compare_with_selected, icon="history").pack(
            side="left", padx=(SPACE["s"], 0)
        )
        secondary_button(bar, "Abrir informe", self.open_history_report, icon="open").pack(side="left", padx=SPACE["s"])
        secondary_button(bar, "Carpeta de informes", self.open_reports_dir, icon="folder").pack(side="left")
        icon_button(bar, "undo", self.refresh_history, "Actualizar lista", size=CONTROL_H).pack(side="right")
        self.history_tree = self._tree(
            page,
            (
                ("fecha", "Fecha", 160, False),
                ("equipo", "Equipo", 160, True),
                ("modo", "Modo", 120, False),
                ("det", "Detectados", 100, False),
                ("unk", "Sospechosos", 110, False),
                ("ok", "Limpios", 90, False),
                ("total", "Total", 80, False),
                ("max", "Score máx.", 100, False),
            ),
        )
        self.history_tree.bind("<Double-1>", lambda _e: self.load_history_entry())

    def _page_settings(self, page: ctk.CTkFrame) -> None:
        scroll = ctk.CTkScrollableFrame(page, fg_color="transparent")
        scroll.pack(fill="both", expand=True)
        scroll.grid_columnconfigure((0, 1), weight=1, uniform="set")

        def section(r: int, col: int, title: str, desc: str) -> ctk.CTkFrame:
            box = card(scroll, title)
            box.grid(row=r, column=col, sticky="nsew", padx=(0 if col == 0 else SPACE["l"], 0), pady=(0, SPACE["l"]))
            ctk.CTkLabel(
                box, text=desc, font=font("caption"), text_color=T("text2"), wraplength=460, justify="left"
            ).pack(anchor="w", padx=SPACE["l"], pady=(SPACE["xs"], SPACE["m"]))
            return box

        vt = section(0, 0, "VirusTotal", "La clave se guarda solo en el archivo .env de tu carpeta de configuración.")
        self.vt_status = Badge(vt, "", "warning")
        self.vt_status.pack(anchor="w", padx=SPACE["l"])
        secondary_button(vt, "Configurar clave…", self.edit_api_key, icon="key", width=200).pack(
            anchor="w", padx=SPACE["l"], pady=SPACE["l"]
        )

        ai = section(
            4, 1, "Asistente de IA", "Groq es gratuito (console.groq.com). Ollama funciona sin Internet en tu PC."
        )
        self.ai_provider = ctk.CTkSegmentedButton(
            ai, values=["Groq", "Ollama"], command=self.set_ai_provider, height=CONTROL_H, **segmented_style()
        )
        self.ai_provider.set("Ollama" if os.environ.get("AI_PROVIDER", "").lower() == "ollama" else "Groq")
        self.ai_provider.pack(anchor="w", padx=SPACE["l"])
        secondary_button(
            ai,
            "Clave de Groq…",
            lambda: self.edit_secret("Groq", "GROQ_API_KEY", "https://console.groq.com/keys"),
            icon="key",
        ).pack(fill="x", padx=SPACE["l"], pady=(SPACE["s"], SPACE["l"]))

        rep = section(3, 0, "Reputación (opcional)", "AbuseIPDB para IPs remotas y MalwareBazaar para hashes.")
        for service, var, url in INTEL_KEYS:
            secondary_button(
                rep, f"Clave de {service}…", lambda s=service, v=var, u=url: self.edit_secret(s, v, u), icon="key"
            ).pack(fill="x", padx=SPACE["l"], pady=(0, SPACE["s"]))
        ctk.CTkFrame(rep, fg_color="transparent", height=SPACE["s"]).pack()

        al = section(
            3, 1, "Alertas e integraciones", "Notificación de Windows y webhook (Slack, Teams, Splunk HEC o JSON)."
        )
        ctk.CTkSwitch(
            al,
            text="Notificar al terminar si la ventana está en segundo plano",
            variable=self.var_notify,
            font=font("body"),
            progress_color=T("accent"),
        ).pack(anchor="w", padx=SPACE["l"], pady=(0, SPACE["s"]))
        self.webhook_entry = ctk.CTkEntry(
            al,
            height=CONTROL_H,
            corner_radius=RADIUS["control"],
            fg_color=T("surface2"),
            border_color=T("border"),
            font=font("body"),
            placeholder_text="https://hooks.slack.com/…  ·  https://…webhook.office.com/…",
        )
        self.webhook_entry.pack(fill="x", padx=SPACE["l"])
        if os.environ.get("WIN11_TRIAGE_WEBHOOK"):
            self.webhook_entry.insert(0, os.environ["WIN11_TRIAGE_WEBHOOK"])
        row = ctk.CTkFrame(al, fg_color="transparent")
        row.pack(fill="x", padx=SPACE["l"], pady=SPACE["s"])
        secondary_button(row, "Guardar", self.save_webhook, width=100).pack(side="left")
        ghost_button(row, "Enviar prueba", self.test_webhook, width=120).pack(side="left", padx=SPACE["s"])
        ctk.CTkSwitch(
            al,
            text="Enviar solo lo nuevo o lo que empeora",
            variable=self.var_alert_new,
            font=font("body"),
            progress_color=T("accent"),
        ).pack(anchor="w", padx=SPACE["l"], pady=(0, SPACE["l"]))

        sch = section(
            4, 0, "Análisis programado", "Se ejecuta con el Programador de tareas y solo avisa si hay novedades."
        )
        self.schedule_seg = ctk.CTkSegmentedButton(sch, values=list(SCHEDULES), height=CONTROL_H, **segmented_style())
        self.schedule_seg.set(self.prefs.get("schedule", "Desactivado"))
        self.schedule_seg.pack(anchor="w", padx=SPACE["l"])
        row = ctk.CTkFrame(sch, fg_color="transparent")
        row.pack(fill="x", padx=SPACE["l"], pady=SPACE["s"])
        ctk.CTkLabel(row, text="Hora", font=font("caption_bold")).pack(side="left")
        self.schedule_at = ctk.CTkEntry(
            row, width=80, height=CONTROL_H, corner_radius=RADIUS["control"], fg_color=T("surface2"),
            border_color=T("border"), font=font("body"),
        )  # fmt: skip
        self.schedule_at.insert(0, self.prefs.get("schedule_at", "09:00"))
        self.schedule_at.pack(side="left", padx=SPACE["s"])
        apply_btn = secondary_button(row, "Aplicar", self.apply_schedule, width=100)
        apply_btn.pack(side="left")
        if not self.windows:
            apply_btn.configure(state="disabled")
        ctk.CTkFrame(sch, fg_color="transparent", height=SPACE["s"]).pack()

        ap = section(0, 1, "Apariencia", "Sigue el tema de Windows o fuerza claro u oscuro.")
        self.appearance = ctk.CTkSegmentedButton(
            ap,
            values=list(APPEARANCE),
            command=self.set_appearance,
            height=CONTROL_H,
            **segmented_style(),
        )
        self.appearance.set(self.prefs.get("appearance", "Oscuro"))
        self.appearance.pack(anchor="w", padx=SPACE["l"], pady=(0, SPACE["s"]))
        ctk.CTkLabel(ap, text="Idioma", font=font("caption_bold")).pack(anchor="w", padx=SPACE["l"])
        self.language = ctk.CTkSegmentedButton(
            ap, values=list(i18n.LANGUAGES.values()), command=self.set_language, height=CONTROL_H, **segmented_style()
        )
        self.language.set(i18n.LANGUAGES.get(self.prefs.get("language", "es"), "Español"))
        self.language.pack(anchor="w", padx=SPACE["l"], pady=(SPACE["xs"], SPACE["l"]))

        tools = section(1, 0, "Herramientas y componentes", "Sysinternals se instala con winget; YARA es opcional.")
        self.tools_frame = ctk.CTkFrame(tools, fg_color="transparent")
        self.tools_frame.pack(fill="x", padx=SPACE["l"], pady=(0, SPACE["l"]))

        data = section(1, 1, "Datos y reglas", "Lista blanca, reglas YARA propias e informes.")
        for text, cmd, ic in (
            ("Editar lista blanca", self.open_whitelist, "shield"),
            ("Reglas YARA propias", self.open_yara_dir, "folder"),
            ("Carpeta de informes", self.open_reports_dir, "folder"),
            ("Carpeta de configuración", lambda: open_path(self.config_dir), "folder"),
        ):
            secondary_button(data, text, cmd, icon=ic, anchor="w").pack(fill="x", padx=SPACE["l"], pady=(0, SPACE["s"]))
        ctk.CTkFrame(data, fg_color="transparent", height=SPACE["s"]).pack()

        upd = section(
            2, 1, "Actualizaciones", f"Versión instalada: {__version__}. Solo se consulta GitHub cuando lo pides."
        )
        secondary_button(upd, "Buscar actualizaciones", self.check_updates, icon="undo", width=220).pack(
            anchor="w", padx=SPACE["l"], pady=(0, SPACE["l"])
        )

        if self.windows and not self.admin:
            adm = section(2, 0, "Privilegios", "Sin administrador, autoruns y los eventos de seguridad ven menos.")
            secondary_button(adm, "Reiniciar como administrador", self.relaunch_admin, icon="shield").pack(
                anchor="w", padx=SPACE["l"], pady=(0, SPACE["l"])
            )

    # ================================================================= navegación
    def show_page(self, key: str) -> None:
        self.page = key
        self.pages[key].tkraise()
        self.nav.set_active(key)
        self.page_title.configure(text=i18n.t(dict((k, t) for k, t, _ in PAGES)[key]))
        self.update_subtitle()

    def update_subtitle(self) -> None:
        text = i18n.t(PAGE_SUBTITLE[self.page])
        if self.result is not None and self.page in ("home", "findings", "network"):
            res = self.result
            mode = f" · {i18n.t('demostración')}" if res.dry_run else ""
            text = f"{res.host} · {res.started:%d/%m/%Y %H:%M}{mode}{self._loaded_suffix}"
        self.subtitle.configure(text=text)

    def focus_search(self) -> None:
        self.show_page("findings")
        self.search.focus_set()

    def _on_search(self) -> None:
        if self.page != "findings" and self.search.get().strip():
            self.show_page("findings")
        self.render_table()

    def toggle_log(self) -> None:
        self.log_visible = not self.log_visible
        if self.log_visible:
            self.log_panel.grid(row=3, column=0, sticky="ew", padx=SPACE["xl"], pady=(0, SPACE["l"]))
            self.log_box.see("end")
        else:
            self.log_panel.grid_remove()

    def set_appearance(self, label: str) -> None:
        ctk.set_appearance_mode(APPEARANCE[label])
        self.prefs["appearance"] = label
        self.update_idletasks()
        self._ui_style()
        for chart in (self.gauge, self.donut, self.attack_chart):
            chart.redraw()
        self.render_all()

    # ================================================================= herramientas
    def refresh_tools(self) -> None:
        self.tools = env_check.check_all()
        for w in self.tools_frame.winfo_children():
            w.destroy()
        rows = [
            (n, st.found, (lambda n=n: self.install_help(n)) if not st.found else None) for n, st in self.tools.items()
        ]
        rows += [
            ("psutil (procesos y red)", collectors_live.available(), None),
            ("pefile (análisis PE)", pe_static.available(), None),
            ("YARA (opcional)", yara_scan.available(), None if yara_scan.available() else self.yara_help),
        ]
        missing = [n for n, st in self.tools.items() if not st.found]
        if missing and env_check.winget_available():
            primary_button(
                self.tools_frame, f"Instalar las {len(missing)} que faltan", self.install_missing, icon="play"
            ).pack(anchor="w", pady=(0, SPACE["s"]))
        for name, ok, fix in rows:
            row = ctk.CTkFrame(self.tools_frame, fg_color="transparent", height=32)
            row.pack(fill="x", pady=1)
            token = "success" if ok else ("warning" if fix else "danger")
            ctk.CTkLabel(
                row, text=glyph("check" if ok else "alert"), font=icon_font(14), text_color=T(token), width=22
            ).pack(side="left")
            ctk.CTkLabel(row, text=name, font=font("body")).pack(side="left", padx=SPACE["s"])
            if fix:
                ghost_button(row, "Instalar", fix, width=80).pack(side="right")
        self.update_env_chips()

    def update_env_chips(self) -> None:
        for w in self.env_chips.winfo_children():
            w.destroy()
        has_key = os.environ.get("VT_API_KEY", "").strip() not in ("", PLACEHOLDER_KEY)
        found = sum(st.found for st in self.tools.values())
        chips = [
            ("Administrador" if self.admin else "Sin administrador", "success" if self.admin else "warning"),
            (f"Sysinternals {found}/{len(self.tools)}", "success" if found == len(self.tools) else "warning"),
            ("VirusTotal" if has_key else "Sin clave VT", "success" if has_key else "warning"),
        ]
        for text, token in chips:
            ctk.CTkButton(
                self.env_chips,
                text=f"● {i18n.t(text)}",
                height=22,
                corner_radius=11,
                fg_color="transparent",
                hover_color=T("surface2"),
                text_color=T(token),
                font=font("caption"),
                width=10,
                command=lambda: self.show_page("settings"),
            ).pack(side="left", padx=(0, SPACE["xs"]))
        self.vt_status.set("Clave configurada" if has_key else "Sin clave", "success" if has_key else "warning")

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
            f"El análisis de contenido funciona sin YARA.\nPara activarlo:\n\n{cmd}\n\n¿Copiar el comando?",
            parent=self,
        ):
            self.to_clipboard(cmd)
            toast(self, "Comando copiado.")

    def install_missing(self) -> None:
        missing = [n for n, st in self.tools.items() if not st.found]
        if not missing or (self.worker and self.worker.is_alive()):
            return
        if not messagebox.askyesno(
            "Instalar herramientas",
            "Se instalarán con winget:\n\n"
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

    def apply_preset(self, name: str) -> None:
        wanted = PRESETS[name]
        for key, var in self.module_vars.items():
            var.set(key in wanted)

    # ================================================================= análisis
    def open_new_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            self.cancel()
            return
        NewScanDialog(self)

    def start_demo(self) -> None:
        self.var_dry.set(True)
        self.apply_preset("Completo")
        self.start()

    def read_options(self) -> TriageOptions | None:
        raw = self.var_vt_limit.get().strip()
        if raw and not raw.isdigit():
            messagebox.showerror("Valor no válido", "El límite de VirusTotal debe ser un número entero.", parent=self)
            return None
        host = self.var_remote.get().strip()
        if host and not valid_host(host):
            messagebox.showerror("Equipo no válido", f"«{host}» no es un nombre de equipo o IP válido.", parent=self)
            return None
        m = {k: v.get() for k, v in self.module_vars.items()}
        return TriageOptions(
            autoruns=m["autoruns"],
            scan_user=m["scan_user"],
            processes=m["processes"],
            events=m["events"],
            sigma=m.get("sigma", False),
            browsers=m.get("browsers", False),
            network=m["network"],
            static=m["static"],
            vt=m["vt"],
            intel=m.get("intel", False),
            quick={k for k, on in m.items() if on} == PRESETS["Rápido"],  # perfil Rápido: autorunsc reducido
            dry_run=self.var_dry.get(),
            vt_limit=int(raw) if raw else None,
            event_days=int(self.var_days.get() or 7),
            config_dir=self.config_dir,
            remote_host=host or None,
        )

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        opts = self.read_options()
        if opts is None:
            return
        if not opts.any_collector:
            messagebox.showwarning("Nada que analizar", "Activa al menos un módulo de recolección.", parent=self)
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
            self.show_page("settings")
            messagebox.showerror(
                "Faltan herramientas",
                "No se encontraron: "
                + ", ".join(missing)
                + ".\n\nInstálalas desde Ajustes o usa el modo demostración.",
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
                "No hay API key configurada. ¿Añadirla ahora?\n\nSi no, el análisis seguirá sin VirusTotal.",
                parent=self,
            )
        ):
            self.edit_api_key()

        self.save_prefs()
        self.result, self.findings, self.reports, self.new_keys, self.has_previous = None, [], [], set(), False
        self.previous = None
        self._loaded_suffix = ""
        self.cancel_flag = threading.Event()
        self.set_running(True)
        self.render_all()
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
        except (WhitelistError, RemoteError) as e:
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
            self.elapsed_label.configure(text=f"{time.monotonic() - self.started_at:3.0f} s")
        self.after(100, self.poll_events)

    def handle_event(self, ev: tuple[Any, ...]) -> None:
        kind = ev[0]
        if kind == "stage":
            self.set_status(ev[1])
            self.indeterminate(True)
        elif kind == "done":
            self.indeterminate(False)
        elif kind == "toast":
            toast(self, ev[1], ev[2])
        elif kind == "agent_tool":
            self.set_status(f"{i18n.t('Consultando')}: {ev[1]}…")
        elif kind == "agent_reply":
            self.indeterminate(False)
            self.chat_send.configure(state="normal")
            self.set_status("Listo.")
            self.chat_write(ev[1].replace("**", ""))
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
            self.set_status(f"VirusTotal {i}/{total} · {summary} ({origin})")
            self.log_line("INFO", f"VT [{i}/{total}] {sha} → {summary} ({origin})")
        elif kind == "vt_wait":
            self.set_status(f"VirusTotal: siguiente consulta en {ev[1]:4.1f} s (límite del plan gratuito)")
        elif kind == "result":
            self.finish(ev[1])
        elif kind == "update":
            _, available, latest, url = ev
            if available:
                toast(
                    self,
                    f"Nueva versión {latest} disponible",
                    "info",
                    8000,
                    action=("Descargar", lambda: webbrowser.open(url)),
                )
            else:
                toast(self, f"Tienes la última versión ({__version__}).", "success")
            self.set_status("Listo.")
        elif kind == "tools_refresh":
            self.set_running(False)
            self.refresh_tools()
            ok = all(st.found for st in self.tools.values())
            toast(
                self,
                "Herramientas listas." if ok else "Alguna herramienta falló: mira el Registro.",
                "success" if ok else "warning",
            )
        elif kind == "cancelled":
            self.set_running(False)
            self.set_status("Análisis cancelado.")
            self.log_line("AVISO", "Análisis cancelado por el usuario.")
            toast(self, "Análisis cancelado.", "warning")
        elif kind == "fatal":
            self.set_running(False)
            self.set_status("Error.")
            self.log_line("ERROR", ev[1])
            messagebox.showerror("Error", ev[1], parent=self)

    def finish(self, res: TriageResult) -> None:
        self.set_running(False)
        self.progress.set(1)
        fmt = FORMATS[self.var_format.get()]
        reports: list[Path] = []
        res.reviews = self.reviews.data
        if fmt:
            reports = report.write_reports(res, self.reports_dir, fmt)
            if fmt not in ("json", "all"):  # el historial necesita siempre el JSON
                reports += report.write_reports(res, self.reports_dir, "json")
            for p in reports:
                self.log_line("INFO", f"Informe guardado: {p}")
        current_json = next((p for p in reports if p.suffix == ".json"), None)
        self.refresh_history()
        self.show_result(res, reports, current_json)
        self.alert_after_scan(res)

        cnt = res.counts()
        took = f" en {res.duration:.0f} s" if res.duration is not None else ""
        self.set_status(f"Análisis terminado{took}.")
        for e in res.errors:
            self.log_line("AVISO", e)
        if cnt[Status.DETECTED]:
            if self.focus_displayof() is None:
                self.bell()

            def view() -> None:
                self.filter_btn.set("Detectados")
                self.render_table()
                self.show_page("findings")

            toast(self, f"{cnt[Status.DETECTED]} elementos detectados", "danger", 6000, action=("Ver", view))
        else:
            toast(self, "Análisis terminado: nada detectado.", "success")

    def show_result(self, res: TriageResult, reports: list[Path], current_json: Path | None) -> None:
        self.result, self.findings, self.reports = res, res.findings, reports
        self.previous = history.previous_of(self.history_entries, current_json, res.started, res.dry_run)
        self.has_previous = self.previous is not None
        self.new_keys = {
            history.key_of(f) for f in self.findings if self.previous and history.key_of(f) not in self.previous.keys
        }
        self.filter_btn.set("Detectados" if res.counts()[Status.DETECTED] else "Todos")
        self.render_all()
        self.show_page("home")

    # ================================================================= renderizado
    def render_all(self) -> None:
        self.render_cards()
        self.render_dashboard()
        self.render_table()
        self.render_connections()
        self.render_process_tree()
        self.update_subtitle()
        self.open_report_btn.configure(state="normal" if self.reports else "disabled")
        if self.result is None:
            self.home_empty.grid(row=0, column=0, rowspan=3, columnspan=3, sticky="nsew")
            self.home_empty.lift()
        else:
            self.home_empty.grid_remove()

    def render_cards(self) -> None:
        res = self.result
        cnt = res.counts() if res else dict.fromkeys(Status, 0)
        prev = self.previous.summary if (self.previous and res) else None
        for key, st in (("detected", Status.DETECTED), ("unknown", Status.UNKNOWN), ("clean", Status.CLEAN)):
            delta = cnt[st] - prev.get(st.value, 0) if prev is not None else None
            self.cards[key].set(cnt[st], delta)
        if res is None:
            self.cards["new"].set(0, hint="Desde el análisis anterior")
        elif self.has_previous:
            self.cards["new"].set(len(self.new_keys), hint="Desde el análisis anterior")
        else:
            self.cards["new"].set("—", hint="Primer análisis de este tipo")

    def render_dashboard(self) -> None:
        res = self.result
        cnt = res.counts() if res else dict.fromkeys(Status, 0)
        self.donut.set(
            [
                (i18n.t("Detectados"), cnt[Status.DETECTED], "danger"),
                (i18n.t("Sospechosos"), cnt[Status.UNKNOWN], "warning"),
                (i18n.t("Limpios"), cnt[Status.CLEAN], "success"),
            ],
            str(sum(cnt.values())),
            i18n.t("elementos"),
        )
        top = max((f.score for f in self.findings), default=0)
        if res is None:
            caption = "sin análisis"
        else:
            caption = "riesgo alto" if top >= 70 else "riesgo medio" if top >= 30 else "riesgo bajo"
        self.gauge.set(top, i18n.t(caption), score_token(top) if res else "text2")
        self.attack_chart.set(
            [(f"{t}  {name}", n, "info", str(n)) for t, name, n in report.attack_summary(self.findings)]
        )
        self.priority_tree.delete(*self.priority_tree.get_children())
        for f in report.top_findings(self.findings):
            self.priority_tree.insert(
                "",
                "end",
                iid=str(self.findings.index(f)),
                text=f"  {i18n.t(STATUS_LABEL[f.status])}",
                image=self.dots[f.status],
                values=(f.score, i18n.t(SOURCE_LABEL.get(f.source, f.source)), f.name, report.why(f, 2)),
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
            if self.review_filter.get() in STATES and self.reviews.state(f.key) != self.review_filter.get():
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
            "rev": lambda r: STATES.index(self.reviews.state(r[1].key)),
        }
        return sorted(rows, key=sorters[key], reverse=reverse)

    def sort_by(self, key: str) -> None:
        current, reverse = self.sort_key
        self.sort_key = (key, not reverse if current == key else False)
        titles = {
            "score": "Score",
            "origen": "Origen",
            "nombre": "Nombre",
            "ruta": "Ruta",
            "why": "Por qué",
            "vt": "VT",
            "rev": "Revisión",
        }
        arrow = " ▴" if self.sort_key[1] else " ▾"
        self.tree.heading("#0", text="Estado" + (arrow if key == "estado" else ""))
        for k, t in titles.items():
            self.tree.heading(k, text=t + (arrow if k == key else ""))
        self.render_table()

    def render_table(self) -> None:
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        rows = self.visible_rows()
        for i, f in rows:
            is_new = history.key_of(f) in self.new_keys
            self.tree.insert(
                "",
                "end",
                iid=str(i),
                text=f"  {i18n.t(STATUS_LABEL[f.status])}",
                image=self.dots[f.status],
                values=(
                    f.score,
                    i18n.t(SOURCE_LABEL.get(f.source, f.source)),
                    ("◆ " if is_new else "") + f.name,
                    elide_middle(f.path or "—", 40),
                    report.why(f) or f.signature,
                    i18n.t(f.vt_summary),
                    self._review_label(f),
                ),
            )
        keep = [s for s in selected if self.tree.exists(s)]
        if keep:
            self.tree.selection_set(keep)
        else:
            self.set_detail(None)
        counts = {"Todos": len(self.findings)}
        for label, st in FILTERS.items():
            if st:
                counts[label] = sum(1 for f in self.findings if f.status is st)
        self.filter_btn.set_counts(counts if self.findings else {})
        if self.findings:
            done = sum(1 for f in self.findings if self.reviews.state(f.key) != PENDING)
            self.review_progress.configure(
                text=f"{i18n.t('Revisados')} {done}/{len(self.findings)}  ·  {i18n.t('teclas')} P R F C"
            )
        else:
            self.review_progress.configure(text="")
        self.nav.set_label("findings", f"Hallazgos  ({len(self.findings)})" if self.findings else "Hallazgos")
        self.render_empty_state(bool(rows))

    def render_empty_state(self, has_rows: bool) -> None:
        if has_rows:
            self.empty_label.place_forget()
            return
        if self.result is None:
            text = "Aún no hay resultados.\nPulsa «Analizar» o prueba con datos de ejemplo."
        elif not self.findings:
            text = "Nada sospechoso con los módulos elegidos."
        else:
            text = "Ningún elemento coincide con el filtro o la búsqueda."
        self.empty_label.configure(text=text)
        self.empty_label.place(relx=0.5, rely=0.5, anchor="center")
        self.empty_label.lift()

    def render_connections(self) -> None:
        self.conn_tree.delete(*self.conn_tree.get_children())
        conns = report.unique_connections(self.findings)
        for cn, st in conns:
            self.conn_tree.insert(
                "",
                "end",
                text=f"  {i18n.t(STATUS_LABEL[st])}",
                image=self.dots[st],
                values=(cn.process, cn.pid, cn.protocol, cn.state, cn.local, cn.remote),
            )
        self.nav.set_label("network", f"Red  ({len(conns)})" if conns else "Red")

    # ================================================================= detalle
    def selected_finding(self) -> Finding | None:
        sel = self.tree.selection()
        return self.findings[int(sel[0])] if sel else None

    def show_detail(self) -> None:
        self.set_detail(self.selected_finding())

    def detail_text(self) -> str:
        """Texto plano del panel de detalle (pruebas y accesibilidad)."""
        return "\n".join(self._detail_lines)

    def _section(self, title: str) -> ctk.CTkFrame:
        title = i18n.t(title)
        ctk.CTkLabel(self.detail_body, text=title.upper(), font=font("overline"), text_color=T("text2")).pack(
            anchor="w", padx=SPACE["m"], pady=(SPACE["l"], SPACE["xs"])
        )
        box = ctk.CTkFrame(self.detail_body, fg_color="transparent")
        box.pack(fill="x", padx=SPACE["m"])
        self._detail_lines.append(f"{title}:")
        return box

    def _kv(self, parent: ctk.CTkFrame, label: str, value: str, monospace: bool = False) -> None:
        ctk.CTkLabel(parent, text=i18n.t(label), font=font("caption"), text_color=T("text2")).pack(anchor="w")
        ctk.CTkLabel(
            parent,
            text=value or "—",
            font=mono(12) if monospace else font("body"),
            wraplength=320,
            justify="left",
            anchor="w",
        ).pack(anchor="w", fill="x", pady=(0, SPACE["s"]))
        self._detail_lines.append(f"{label}: {value}")

    def set_detail(self, f: Finding | None) -> None:
        self.selected = f
        self._detail_lines = []
        for w in self.detail_body.winfo_children():
            w.destroy()
        if f is None:
            ctk.CTkLabel(
                self.detail_body,
                text="Selecciona un elemento para ver por qué es sospechoso.",
                font=font("body"),
                text_color=T("text2"),
                wraplength=300,
                justify="left",
            ).pack(anchor="w", padx=SPACE["m"], pady=SPACE["l"])
            for b in (self.vt_btn, self.copy_hash_btn, self.more_btn):
                b.configure(state="disabled")
            return
        head = ctk.CTkFrame(self.detail_body, fg_color="transparent")
        head.pack(fill="x", padx=SPACE["m"], pady=(SPACE["m"], 0))
        Badge(head, i18n.t(STATUS_LABEL[f.status]), STATUS_TOKEN[f.status]).pack(side="left")
        ctk.CTkLabel(head, text=str(f.score), font=font("display"), text_color=T(score_token(f.score))).pack(
            side="right"
        )
        ctk.CTkLabel(head, text="score", font=font("caption"), text_color=T("text2")).pack(
            side="right", padx=(0, SPACE["xs"]), pady=(SPACE["m"], 0)
        )
        ctk.CTkLabel(self.detail_body, text=f.name, font=font("subtitle"), wraplength=330, justify="left").pack(
            anchor="w", padx=SPACE["m"], pady=(SPACE["s"], 0)
        )
        ctk.CTkLabel(
            self.detail_body,
            text=f"{i18n.t(SOURCE_LABEL.get(f.source, f.source))} · {f.category or '—'}",
            font=font("caption"),
            text_color=T("text2"),
            wraplength=330,
            justify="left",
        ).pack(anchor="w", padx=SPACE["m"])
        self._detail_lines.append(f"{f.status.value} · score {f.score} — {f.name}")

        box = self._section("Revisión del analista")
        rv = self.reviews.get(f.key)
        grid = ctk.CTkFrame(box, fg_color="transparent")
        grid.pack(fill="x")
        grid.grid_columnconfigure((0, 1), weight=1, uniform="rv")
        soft = {"text2": "surface2", "info": "info_soft", "success": "success_soft", "danger": "danger_soft"}
        for i, st in enumerate(STATES):
            token = STATE_TOKEN[st]
            active = st == rv["state"]
            key = next(k for k, v in STATE_KEYS.items() if v == st).upper()
            ctk.CTkButton(
                grid,
                text=f"{i18n.t(st)}  ·  {key}",
                height=30,
                corner_radius=15,
                border_width=1,
                font=font("caption_bold" if active else "caption"),
                fg_color=T(soft[token]) if active else "transparent",
                border_color=T(token) if active else T("border"),
                text_color=T(token) if active and token != "text2" else T("text"),
                hover_color=T("surface2"),
                command=lambda s_=st: self.set_review(s_),
            ).grid(
                row=i // 2, column=i % 2, sticky="ew", padx=(0 if i % 2 == 0 else SPACE["xs"], 0), pady=(0, SPACE["xs"])
            )
        self.note_box = ctk.CTkTextbox(
            box,
            height=64,
            fg_color=T("surface2"),
            border_width=1,
            border_color=T("border"),
            font=font("body"),
            wrap="word",
        )
        self.note_box.pack(fill="x", pady=(SPACE["s"], SPACE["xs"]))
        if rv.get("note"):
            self.note_box.insert("1.0", rv["note"])
        self.save_note_btn = ghost_button(box, "Guardar nota", self.save_note, width=120)
        self.save_note_btn.pack(anchor="e")
        self._detail_lines.append(f"Revisión: {rv['state']} {rv.get('note', '')}")

        if f.status != Status.CLEAN:
            adv = playbook.advice_for(f)
            box = self._section("¿Qué hago con esto?")
            panel = ctk.CTkFrame(box, fg_color=T("accent_soft"), corner_radius=RADIUS["control"])
            panel.pack(fill="x", pady=(0, SPACE["xs"]))
            ctk.CTkLabel(
                panel, text=adv.summary, font=font("body_bold"), wraplength=300, justify="left", anchor="w"
            ).pack(anchor="w", fill="x", padx=SPACE["m"], pady=(SPACE["m"], SPACE["xs"]))
            for i, step in enumerate(adv.steps, 1):
                ctk.CTkLabel(
                    panel, text=f"{i}. {step}", font=font("body"), wraplength=300, justify="left", anchor="w"
                ).pack(anchor="w", fill="x", padx=SPACE["m"], pady=(0, SPACE["xs"]))
            ctk.CTkFrame(panel, fg_color="transparent", height=SPACE["xs"]).pack()
            self._detail_lines.append(playbook.as_text(f))

        if f.unique_signals:
            box = self._section("Por qué")
            for s in f.unique_signals:
                row = ctk.CTkFrame(box, fg_color="transparent")
                row.pack(fill="x", pady=(0, SPACE["xs"]))
                token = "danger" if s.weight >= 50 else ("warning" if s.weight > 0 else "success")
                Badge(row, f"{s.weight:+d}", token).pack(side="left", anchor="n")
                txt = i18n.t(s.title) + (f"  ·  {s.attack}" if s.attack else "")
                ctk.CTkLabel(row, text=txt, font=font("body"), wraplength=260, justify="left", anchor="w").pack(
                    side="left", padx=SPACE["s"], fill="x"
                )
                if s.evidence:
                    ctk.CTkLabel(
                        box,
                        text=s.evidence[:220],
                        font=mono(11),
                        text_color=T("text2"),
                        wraplength=300,
                        justify="left",
                        anchor="w",
                    ).pack(anchor="w", fill="x", padx=(52, 0), pady=(0, SPACE["s"]))
                self._detail_lines.append(f"{s.weight:+d} {s.title} {s.attack} {s.evidence}")

        box = self._section("Archivo")
        self._kv(box, "Ruta", f.path, monospace=True)
        self._kv(box, "SHA-256", f.sha256 or "no disponible", monospace=True)
        self._kv(box, "Editor · firma", f"{f.publisher} · {f.signature}")
        if f.cmdline or f.pid:
            box = self._section("Ejecución")
            if f.cmdline:
                self._kv(box, "Línea de comandos", f.cmdline[:500], monospace=True)
            if f.pid:
                self._kv(box, "Proceso", f"PID {f.pid} · padre {f.parent or '?'} ({f.ppid})")
        if f.location:
            self._kv(box, "Ubicación", f.location, monospace=True)
        if f.connections:
            box = self._section("Red")
            for cn in f.connections:
                self._kv(box, f"{cn.protocol} · {cn.state}", f"{cn.local} → {cn.remote}", monospace=True)
        vt = f.vt or {}
        box = self._section("VirusTotal")
        label = f" · {vt['label']}" if vt.get("label") else ""
        self._kv(box, "Resultado", f"{i18n.t(f.vt_summary)}{label}")

        self.vt_btn.configure(state="normal" if f.sha256 else "disabled")
        self.copy_hash_btn.configure(state="normal" if f.sha256 else "disabled")
        self.more_btn.configure(state="normal")
        with contextlib.suppress(AttributeError, tk.TclError):
            self.detail_body._parent_canvas.yview_moveto(0)

    def _review_label(self, f: Finding) -> str:
        rv = self.reviews.get(f.key)
        mark = {"Pendiente": "", "En revisión": "◐ ", "Falso positivo": "✓ ", "Confirmado": "✕ "}[rv["state"]]
        return f"{mark}{rv['state']}" + (" ✎" if rv.get("note") else "")

    def _reselect(self, sel: tuple[str, ...]) -> None:
        if sel and self.tree.exists(sel[0]):
            self.tree.selection_set(sel[0])
            self.tree.focus(sel[0])
            self.tree.see(sel[0])

    def set_review(self, state: str) -> None:
        f = self.selected_finding()
        if f is None:
            return
        self.reviews.set(f.key, state=state, name=f.name)
        sel = self.tree.selection()
        self.render_table()
        self._reselect(sel)
        self.set_status(f"«{f.name}» marcado como {state}.")

    def save_note(self) -> None:
        f = self.selected_finding()
        if f is None:
            return
        self.reviews.set(f.key, note=self.note_box.get("1.0", "end"), name=f.name)
        sel = self.tree.selection()
        self.render_table()
        self._reselect(sel)
        flash_button(self.save_note_btn, f"{glyph('check')}  Guardada")

    def compare_with_selected(self) -> None:
        e = self.selected_history()
        if e is None or self.result is None:
            toast(self, "Carga o ejecuta un análisis y selecciona otro del historial para compararlos.")
            return
        try:
            other = report.load_json(e.path)
        except (OSError, ValueError, KeyError, TypeError) as err:
            messagebox.showerror("No se pudo cargar", f"{e.path.name}: {err}", parent=self)
            return
        prev, cur = (other, self.result) if other.started <= self.result.started else (self.result, other)
        CompareDialog(self, prev, cur, f"{prev.started:%d/%m/%Y %H:%M} → {cur.started:%d/%m/%Y %H:%M}")

    def export_evidence(self, path: Path | None = None) -> Path | None:
        if self.result is None:
            toast(self, "Aún no hay resultados que exportar.")
            return None
        if path is None:
            chosen = filedialog.asksaveasfilename(
                parent=self,
                defaultextension=".zip",
                initialfile=f"{self.result.file_stem}_evidencias.zip",
                filetypes=[("ZIP", "*.zip")],
            )
            if not chosen:
                return None
            path = Path(chosen)
        self.result.reviews = self.reviews.data
        report.write_evidence_zip(self.result, path, self.new_keys)
        self.log_line("INFO", f"Paquete de evidencias: {path}")
        target = path
        toast(
            self, f"Paquete creado: {path.name}", "success", action=("Abrir carpeta", lambda: open_path(target.parent))
        )
        return path

    def check_updates(self) -> None:
        from ..updates import check_latest

        self.set_status("Buscando actualizaciones…")

        def work() -> None:
            try:
                info = check_latest()
                self.events.put(("update", info.available, info.latest, info.url))
            except Exception as e:
                self.events.put(("log", "AVISO", f"No se pudo comprobar si hay actualizaciones: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def jump_to_priority(self) -> None:
        sel = self.priority_tree.selection()
        if not sel:
            return
        self.filter_btn.set("Todos")
        self.search.delete(0, "end")
        self.only_new.set(False)
        self.render_table()
        self.show_page("findings")
        if self.tree.exists(sel[0]):
            self.tree.selection_set(sel[0])
            self.tree.see(sel[0])

    # ================================================================= historial
    def refresh_history(self) -> None:
        self.history_entries = history.list_reports(self.reports_dir)
        self.history_tree.delete(*self.history_tree.get_children())
        for n, e in enumerate(self.history_entries):
            s = e.summary
            st = Status.DETECTED if s.get("DETECTADO") else (Status.UNKNOWN if s.get("DESCONOCIDO") else Status.CLEAN)
            self.history_tree.insert(
                "",
                "end",
                iid=str(n),
                text=f"  {i18n.t(STATUS_LABEL[st])}",
                image=self.dots[st],
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
            )
        n = len(self.history_entries)
        self.nav.set_label("history", f"Historial  ({n})" if n else "Historial")

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
        self._loaded_suffix = i18n.t(" · cargado del historial")
        self.update_subtitle()
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
                toast(self, "Técnicas: " + ", ".join(f"{t} {technique_name(t)}" for t in f.attack[:4]), "info")

    def copy_hash(self) -> None:
        f = self.selected_finding()
        if f and f.sha256:
            self.to_clipboard(f.sha256)
            flash_button(self.copy_hash_btn, f"{glyph('check')}  Copiado")

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
        """Ignora la ruta o el hash al instante, con «Deshacer» en lugar de pedir confirmación antes."""
        f = self.selected_finding()
        if not f or self.result is None:
            return
        value = f.sha256 if by_hash else f.path
        if not value:
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
        snapshot = (copy.copy(self.result.sections), self.result.whitelisted)
        wl = Whitelist(hashes=[value]) if by_hash else Whitelist(paths=[value])
        for section, items in list(self.result.sections.items()):
            kept, removed = wl.filter(items)
            self.result.sections[section] = kept
            self.result.whitelisted += removed
        self.findings = self.result.findings
        self.render_all()
        self.log_line("INFO", f"Añadido a whitelist.json: {value}")

        def undo() -> None:
            if by_hash:
                remove_from_whitelist(file, sha256=value)
            else:
                remove_from_whitelist(file, path=value)
            if self.result is not None:
                self.result.sections, self.result.whitelisted = snapshot
                self.findings = self.result.findings
                self.render_all()
            self.log_line("INFO", f"Deshecho: {value} ya no se ignora")

        what = "este hash" if by_hash else "esta ruta"
        toast(self, f"Se ignorará {what} en próximos análisis.", "success", 6000, action=("Deshacer", undo))

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
            flash_button(self.copy_ip_btn, f"{glyph('check')}  Copiada")

    def popup_finding_menu(self, event: tk.Event | None) -> None:
        if event is not None:
            row = self.tree.identify_row(event.y)
            if not row:
                return
            self.tree.selection_set(row)
            self.update_idletasks()
        f = self.selected_finding()
        if f is None:
            return
        menu = themed_menu(self)
        menu.add_command(label="Ver en VirusTotal", command=self.open_vt, state="normal" if f.sha256 else "disabled")
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
        if event is not None:
            x, y = event.x_root, event.y_root
        else:
            x, y = self.more_btn.winfo_rootx(), self.more_btn.winfo_rooty() + self.more_btn.winfo_height()
        menu.tk_popup(x, y)

    def popup_connection_menu(self, event: tk.Event) -> None:
        row = self.conn_tree.identify_row(event.y)
        if not row:
            return
        self.conn_tree.selection_set(row)
        menu = themed_menu(self)
        menu.add_command(label="Buscar IP en VirusTotal", command=self.lookup_ip)
        menu.add_command(label="Copiar IP remota", command=self.copy_ip)
        menu.tk_popup(event.x_root, event.y_root)

    # ================================================================= exportar
    def show_export_menu(self) -> None:
        menu = themed_menu(self)
        st = "normal" if self.result is not None else "disabled"
        menu.add_command(label="CSV de la vista actual…        Ctrl+E", command=self.export_csv, state=st)
        menu.add_separator()
        for label, fmt in (
            ("Informe HTML…", "html"),
            ("Resumen ejecutivo (PDF)…", "pdf"),
            ("Informe Markdown…", "md"),
            ("JSON (esquema v2)…", "json"),
        ):
            menu.add_command(label=label, command=lambda f=fmt: self.export_report(f), state=st)
        menu.add_separator()
        menu.add_command(label="Paquete de evidencias (.zip)…", command=self.export_evidence, state=st)
        menu.tk_popup(self.export_btn.winfo_rootx(), self.export_btn.winfo_rooty() + self.export_btn.winfo_height() + 4)

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
        report.write_csv(path, [f for _, f in self.visible_rows()], self.reviews.data, self.new_keys)
        self.log_line("INFO", f"CSV exportado: {path}")
        toast(self, f"Exportado: {path.name}", "success", action=("Abrir", lambda: open_path(path)))
        return path

    def export_report(self, fmt: str) -> None:
        if self.result is None:
            return
        ext = {"html": ".html", "md": ".md", "json": ".json", "pdf": ".pdf"}[fmt]
        chosen = filedialog.asksaveasfilename(
            parent=self, defaultextension=ext, initialfile=f"{self.result.file_stem}{ext}"
        )
        if not chosen:
            return
        target = Path(chosen)
        self.result.reviews = self.reviews.data
        written = report.write_reports(self.result, target.parent, fmt)[0]
        if written != target:
            written.replace(target)
        toast(self, f"Exportado: {target.name}", "success", action=("Abrir", lambda: open_path(target)))

    # ================================================================= configuración
    def set_ai_provider(self, label: str) -> None:
        self.store_env("AI_PROVIDER", label.lower())
        self.update_agent_status()
        toast(self, f"Asistente: {label}.", "success")

    def set_language(self, label: str) -> None:
        code = next((k for k, v in i18n.LANGUAGES.items() if v == label), "es")
        if code == self.prefs.get("language", "es"):
            return
        self.prefs["language"] = code
        settings.save(self.config_dir, self.prefs)
        msg = (
            "Restart the application to change the language."
            if code == "en"
            else ("Reinicia la aplicación para cambiar el idioma.")
        )
        toast(self, msg, "accent", ms=6000)

    def edit_secret(self, service: str, var: str, url: str) -> None:
        dlg = SecretDialog(self, os.environ.get(var, ""), service=service, url=url)
        self.wait_window(dlg)
        if dlg.value is None:
            return
        self.store_env(var, dlg.value)
        self.update_agent_status()
        toast(self, f"Clave de {service} guardada.", "success")

    def store_env(self, var: str, value: str) -> None:
        self.env_file.parent.mkdir(parents=True, exist_ok=True)
        self.env_file.touch(exist_ok=True)
        set_key(str(self.env_file), var, value, quote_mode="never")
        os.environ[var] = value
        self.log_line("INFO", f"{var} guardada en {self.env_file}")

    def save_webhook(self) -> None:
        url = self.webhook_entry.get().strip()
        if url and not url.startswith("https://"):
            messagebox.showerror("Webhook", "La URL del webhook debe empezar por https://", parent=self)
            return
        self.store_env("WIN11_TRIAGE_WEBHOOK", url)
        toast(self, "Webhook guardado." if url else "Webhook desactivado.", "success")

    def test_webhook(self) -> None:
        url = self.webhook_entry.get().strip()
        if not url:
            toast(self, "Escribe primero la URL del webhook.", "warning")
            return
        res = self.result or TriageResult(
            host=platform.node() or "host", user="", started=datetime.now(), dry_run=False, admin=False, tools={}
        )

        def work() -> None:
            try:
                kind = alerts.send_webhook(url, res, alerts.select_alertable(res)[:5])
                self.events.put(("toast", f"Prueba enviada ({kind}).", "success"))
            except requests.RequestException as e:
                self.events.put(("toast", f"No se pudo enviar: {e}", "error"))

        threading.Thread(target=work, daemon=True).start()

    def apply_schedule(self) -> None:
        choice = SCHEDULES[self.schedule_seg.get()]
        at = self.schedule_at.get().strip() or "09:00"
        try:
            if choice == "off":
                with contextlib.suppress(RuntimeError):
                    scheduler.delete()
                msg = "Análisis programado desactivado."
            else:
                scheduler.create(self.config_dir, choice, at, admin=self.admin)
                msg = f"Análisis programado: {self.schedule_seg.get().lower()} a las {at}."
        except (RuntimeError, OSError, ValueError) as e:
            messagebox.showerror("Análisis programado", str(e), parent=self)
            return
        self.prefs["schedule"], self.prefs["schedule_at"] = self.schedule_seg.get(), at
        settings.save(self.config_dir, self.prefs)
        self.log_line("INFO", msg)
        toast(self, msg, "success")

    def alert_after_scan(self, res: TriageResult) -> None:
        """Notificación y webhook al terminar (en segundo plano para no bloquear la ventana)."""
        want_toast = self.var_notify.get() and self.focus_displayof() is None
        webhook = "" if res.dry_run else os.environ.get("WIN11_TRIAGE_WEBHOOK", "").strip()
        if not (want_toast or webhook):
            return
        previous = None
        if self.var_alert_new.get() and self.previous is not None:
            with contextlib.suppress(OSError, ValueError, KeyError):
                previous = report.load_json(self.previous.path)
        items = alerts.select_alertable(res, previous, only_new=previous is not None)
        if previous is not None and not items:
            return
        title, body = alerts.summary_text(res, items, previous is not None)

        def work() -> None:
            if want_toast:
                alerts.notify_toast(f"win11-triage · {title}", body)
            if webhook:
                try:
                    alerts.send_webhook(webhook, res, items, previous is not None)
                except requests.RequestException as e:
                    self.events.put(("log", "AVISO", f"Webhook: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def edit_api_key(self) -> None:
        dlg = SecretDialog(self, os.environ.get("VT_API_KEY", ""))
        self.wait_window(dlg)
        if dlg.value is None:
            return
        self.env_file.parent.mkdir(parents=True, exist_ok=True)
        self.env_file.touch(exist_ok=True)
        set_key(str(self.env_file), "VT_API_KEY", dlg.value, quote_mode="never")
        os.environ["VT_API_KEY"] = dlg.value
        self.update_env_chips()
        self.log_line("INFO", f"Clave de VirusTotal guardada en {self.env_file}")
        toast(self, "Clave de VirusTotal guardada.", "success")

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
        toast(self, "Copia aquí tus reglas .yar: se cargarán en el próximo análisis.", "info")

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
        self.prefs["event_days"] = int(self.var_days.get() or 7)
        self.prefs["vt_limit"] = self.var_vt_limit.get().strip()
        self.prefs["format"] = self.var_format.get()
        self.prefs["notify"] = bool(self.var_notify.get())
        self.prefs["alert_new"] = bool(self.var_alert_new.get())
        with contextlib.suppress(tk.TclError):
            self.prefs["geometry"] = self.geometry()
        settings.save(self.config_dir, self.prefs)

    # ================================================================= utilidades
    def set_running(self, running: bool) -> None:
        if running:
            self.started_at = time.monotonic()
            self.elapsed_label.configure(text="0 s")
            self.progress.set(0)
            self.run_btn.configure(
                text=f"{glyph('stop')}  {i18n.t('Cancelar')}",
                fg_color=T("surface2"),
                hover_color=T("border"),
                text_color=T("danger"),
                command=self.cancel,
            )
        else:
            self.indeterminate(False)
            self.run_btn.configure(
                text=f"{glyph('play')}  {i18n.t('Analizar')}",
                fg_color=T("accent"),
                hover_color=T("accent_hover"),
                text_color="#FFFFFF",
                command=self.open_new_scan,
            )
        self.open_report_btn.configure(state="normal" if (self.reports and not running) else "disabled")

    def indeterminate(self, on: bool) -> None:
        if on:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate")

    def set_status(self, text: str) -> None:
        text = i18n.t(text)
        self.status_label.configure(text=text if len(text) < 110 else text[:107] + "…")

    def log_line(self, level: str, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{datetime.now():%H:%M:%S}  {level:<5}  {text}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
        if level == "ERROR":
            self.log_btn.configure(text_color=T("danger"))

    def to_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    def on_close(self) -> None:
        self.cancel_flag.set()
        self.save_prefs()
        self.destroy()
