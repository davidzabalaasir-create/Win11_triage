"""Diálogo «Nuevo análisis»: perfiles, módulos agrupados y opciones."""

from __future__ import annotations

from typing import TYPE_CHECKING

import customtkinter as ctk

from .theme import CONTROL_H, RADIUS, SPACE, T, font
from .widgets import Modal, Tooltip, option_style, primary_button, secondary_button, segmented_style

if TYPE_CHECKING:
    from .app import TriageApp

GROUPS = (
    (
        "Recolección",
        (
            ("autoruns", "Persistencia", "Programas que arrancan solos (autorunsc)"),
            ("scan_user", "Carpetas de usuario", "Ejecutables sin firma en Temp y AppData"),
            ("processes", "Procesos en ejecución", "Rutas raras, suplantación, Office → consola"),
            ("events", "Eventos de Windows", "Servicios y tareas nuevos, detecciones de Defender"),
        ),
    ),
    (
        "Enriquecimiento",
        (
            ("network", "Conexiones de red", "Qué proceso sospechoso habla con el exterior"),
            ("static", "Análisis de contenido", "Empaquetadores, imports de inyección, YARA"),
            ("vt", "VirusTotal", "Reputación de cada hash (15 s por consulta nueva)"),
        ),
    ),
)
PRESETS = {
    "Rápido": {"autoruns", "scan_user", "processes", "network"},
    "Completo": {key for _, items in GROUPS for key, _, _ in items},
}
FORMATS = ("HTML", "Markdown", "JSON", "Todos (HTML+MD+JSON)", "No guardar")


class NewScanDialog(Modal):
    def __init__(self, app: TriageApp) -> None:
        super().__init__(app, "Nuevo análisis", "740x700")
        self.app = app
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(side="bottom", fill="x", padx=SPACE["xl"], pady=SPACE["xl"])
        primary_button(actions, "Iniciar análisis", self._start, icon="play", width=180).pack(side="right")
        secondary_button(actions, "Cancelar", self.destroy, width=110).pack(side="right", padx=SPACE["s"])
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=SPACE["xl"], pady=(SPACE["xl"], 0))

        ctk.CTkLabel(body, text="Nuevo análisis", font=font("title")).pack(anchor="w")
        ctk.CTkLabel(
            body,
            text="Elige un perfil o personaliza los módulos. Se recordará para la próxima vez.",
            font=font("caption"),
            text_color=T("text2"),
        ).pack(anchor="w", pady=(SPACE["xs"], SPACE["l"]))

        self.profile = ctk.CTkSegmentedButton(
            body, values=[*PRESETS, "Personalizado"], command=self._apply_profile, height=CONTROL_H, **segmented_style()
        )
        self.profile.pack(anchor="w")
        self.profile.set(self._current_profile())

        cols = ctk.CTkFrame(body, fg_color="transparent")
        cols.pack(fill="x", pady=SPACE["l"])
        cols.grid_columnconfigure((0, 1), weight=1, uniform="g")
        for i, (title, items) in enumerate(GROUPS):
            box = ctk.CTkFrame(
                cols, fg_color=T("surface"), corner_radius=RADIUS["card"], border_width=1, border_color=T("border")
            )
            box.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else SPACE["s"], 0 if i else SPACE["s"]))
            ctk.CTkLabel(box, text=title.upper(), font=font("overline"), text_color=T("text2")).pack(
                anchor="w", padx=SPACE["l"], pady=(SPACE["l"], SPACE["xs"])
            )
            for key, label, desc in items:
                ctk.CTkSwitch(
                    box,
                    text=label,
                    variable=app.module_vars[key],
                    font=font("body_bold"),
                    progress_color=T("accent"),
                    command=lambda: self.profile.set(self._current_profile()),
                ).pack(anchor="w", padx=SPACE["l"], pady=(SPACE["s"], 0))
                ctk.CTkLabel(
                    box, text=desc, font=font("caption"), text_color=T("text2"), wraplength=260, justify="left"
                ).pack(anchor="w", padx=(SPACE["l"] + 50, SPACE["l"]))
            ctk.CTkFrame(box, fg_color="transparent", height=SPACE["m"]).pack()

        opts = ctk.CTkFrame(
            body, fg_color=T("surface"), corner_radius=RADIUS["card"], border_width=1, border_color=T("border")
        )
        opts.pack(fill="x")
        opts.grid_columnconfigure((0, 1, 2), weight=1, uniform="o")
        self._field(
            opts,
            0,
            "Eventos de los últimos",
            ctk.CTkOptionMenu(opts, values=["1", "7", "30", "90"], variable=app.var_days, **option_style()),
            "días",
        )
        self._field(
            opts,
            1,
            "Límite de consultas a VirusTotal",
            ctk.CTkEntry(
                opts,
                textvariable=app.var_vt_limit,
                height=CONTROL_H,
                corner_radius=RADIUS["control"],
                fg_color=T("surface2"),
                border_color=T("border"),
                font=font("body"),
            ),
            "Vacío = sin límite. Las consultas en caché no cuentan.",
        )
        self._field(
            opts,
            2,
            "Guardar informe como",
            ctk.CTkOptionMenu(opts, values=list(FORMATS), variable=app.var_format, **option_style()),
            "Se guarda en la carpeta de informes",
        )
        dry = ctk.CTkSwitch(
            opts,
            text="Modo demostración (datos de ejemplo, sin red)",
            variable=app.var_dry,
            font=font("body"),
            progress_color=T("accent"),
        )
        dry.grid(row=3, column=0, columnspan=3, sticky="w", padx=SPACE["l"], pady=(SPACE["s"], SPACE["l"]))
        if not app.windows:
            dry.configure(state="disabled")

        self.bind("<Return>", lambda _e: self._start())

    def _field(self, parent: ctk.CTkFrame, col: int, label: str, widget: ctk.CTkBaseClass, hint: str) -> None:
        ctk.CTkLabel(parent, text=label, font=font("caption_bold")).grid(
            row=0, column=col, sticky="w", padx=SPACE["l"], pady=(SPACE["l"], SPACE["xs"])
        )
        widget.grid(row=1, column=col, sticky="ew", padx=SPACE["l"])
        if hint:
            Tooltip(widget, hint)

    def _current_profile(self) -> str:
        on = {k for k, v in self.app.module_vars.items() if v.get()}
        return next((name for name, mods in PRESETS.items() if mods == on), "Personalizado")

    def _apply_profile(self, name: str) -> None:
        if name in PRESETS:
            self.app.apply_preset(name)

    def _start(self) -> None:
        self.destroy()
        self.app.start()
