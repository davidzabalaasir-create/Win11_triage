"""Componentes de la interfaz, construidos sobre los tokens de ``theme``."""

from __future__ import annotations

import math
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from collections.abc import Callable
from typing import Any

import customtkinter as ctk
from PIL import Image

from .. import __copyright__, __version__
from ..engine import PLACEHOLDER_KEY
from .theme import (
    CONTROL_H,
    ICON_PNG,
    RADIUS,
    SPACE,
    T,
    c,
    font,
    glyph,
    icon_font,
    tk_font,
    ui_family,
)

REPO_URL = "https://github.com/davidzabalaasir-create/Win11_triage"


def load_logo(size: int) -> ctk.CTkImage | None:
    try:
        img = Image.open(ICON_PNG)
    except OSError:
        return None
    return ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))


def make_dot(master: tk.Misc, color: str, size: int = 10) -> tk.PhotoImage:
    """Punto de color para la columna de estado de un Treeview (ttk no colorea celdas sueltas)."""
    img = tk.PhotoImage(master=master, width=size + 6, height=size)
    r = size / 2 - 0.5
    for y in range(size):
        row = []
        for x in range(size):
            row.append(color if (x - r) ** 2 + (y - r) ** 2 <= r * r else "")
        for x, col in enumerate(row):
            if col:
                img.put(col, (x, y))
    return img


# ------------------------------------------------------------------ botones
def primary_button(
    master: Any, text: str, command: Callable | None = None, icon: str | None = None, **kw: Any
) -> ctk.CTkButton:
    label = f"{glyph(icon)}  {text}" if icon else text
    return ctk.CTkButton(
        master,
        text=label,
        command=command,
        height=CONTROL_H,
        corner_radius=RADIUS["control"],
        fg_color=T("accent"),
        hover_color=T("accent_hover"),
        text_color="#FFFFFF",
        font=font("body_bold"),
        **kw,
    )


def secondary_button(
    master: Any, text: str, command: Callable | None = None, icon: str | None = None, **kw: Any
) -> ctk.CTkButton:
    label = f"{glyph(icon)}  {text}" if icon else text
    kw.setdefault("height", CONTROL_H)
    return ctk.CTkButton(
        master,
        text=label,
        command=command,
        corner_radius=RADIUS["control"],
        fg_color=T("surface2"),
        hover_color=T("border"),
        border_width=1,
        border_color=T("border"),
        text_color=T("text"),
        font=font("body"),
        **kw,
    )


def ghost_button(master: Any, text: str, command: Callable | None = None, **kw: Any) -> ctk.CTkButton:
    kw.setdefault("height", 30)
    kw.setdefault("text_color", T("accent"))
    return ctk.CTkButton(
        master,
        text=text,
        command=command,
        corner_radius=RADIUS["control"],
        fg_color="transparent",
        hover_color=T("surface2"),
        font=font("body"),
        **kw,
    )


def icon_button(
    master: Any, icon: str, command: Callable | None = None, tooltip: str = "", size: int = 32
) -> ctk.CTkButton:
    b = ctk.CTkButton(
        master,
        text=glyph(icon),
        command=command,
        width=size,
        height=size,
        corner_radius=RADIUS["control"],
        fg_color="transparent",
        hover_color=T("surface2"),
        text_color=T("text2"),
        font=icon_font(16),
    )
    if tooltip:
        Tooltip(b, tooltip)
    return b


def flash_button(button: ctk.CTkButton, text: str = "✓ Copiado", ms: int = 1200) -> None:
    """Confirma una acción cambiando el texto del botón un instante (sin toasts)."""
    original = button.cget("text")
    button.configure(text=text)
    button.after(ms, lambda: button.winfo_exists() and button.configure(text=original))


def segmented_style() -> dict[str, Any]:
    """Estilo común de CTkSegmentedButton (el por defecto de CTk es gris/azul intenso)."""
    return {
        "fg_color": T("surface2"),
        "unselected_color": T("surface2"),
        "unselected_hover_color": T("border"),
        "selected_color": T("accent"),
        "selected_hover_color": T("accent_hover"),
        "text_color": T("text"),
        "font": font("body"),
        "corner_radius": RADIUS["control"],
    }


def option_style() -> dict[str, Any]:
    """Estilo común de CTkOptionMenu como campo de formulario neutro."""
    return {
        "fg_color": T("surface2"),
        "button_color": T("surface2"),
        "button_hover_color": T("border"),
        "text_color": T("text"),
        "dropdown_fg_color": T("surface2"),
        "dropdown_hover_color": T("accent_soft"),
        "dropdown_text_color": T("text"),
        "font": font("body"),
        "dropdown_font": font("body"),
        "corner_radius": RADIUS["control"],
        "height": CONTROL_H,
    }


# ------------------------------------------------------------------ tooltip
class Tooltip:
    def __init__(self, widget: tk.Misc, text: str, delay: int = 450) -> None:
        self.widget, self.text, self.delay = widget, text, delay
        self._after: str | None = None
        self._tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _e: tk.Event) -> None:
        self._after = self.widget.after(self.delay, self._show)

    def _show(self) -> None:
        if self._tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 4
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self._tip = tk.Toplevel(self.widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        tk.Label(
            self._tip,
            text=self.text,
            bg=c("surface2"),
            fg=c("text"),
            bd=1,
            relief="solid",
            padx=8,
            pady=4,
            font=tk_font("caption"),
            highlightthickness=0,
        ).pack()

    def _hide(self, _e: tk.Event | None = None) -> None:
        if self._after:
            self.widget.after_cancel(self._after)
            self._after = None
        if self._tip:
            self._tip.destroy()
            self._tip = None


# ------------------------------------------------------------------ badge y chips
class Badge(ctk.CTkLabel):
    """Pastilla de estado: texto del color del estado sobre su versión suave."""

    def __init__(self, master: Any, text: str = "", token: str = "accent", **kw: Any) -> None:
        super().__init__(master, text=text, corner_radius=10, height=22, font=font("caption_bold"), **kw)
        self.set(text, token)

    def set(self, text: str, token: str) -> None:
        soft = (
            f"{token}_soft"
            if f"{token}_soft" in ("danger_soft", "warning_soft", "success_soft", "info_soft", "accent_soft")
            else "surface2"
        )
        self.configure(text=f"  {text}  ", text_color=T(token), fg_color=T(soft))


class FilterChips(ctk.CTkFrame):
    """Filtros tipo chip con contador. API compatible con CTkSegmentedButton (get/set)."""

    def __init__(self, master: Any, values: list[str], command: Callable[[str], None] | None = None) -> None:
        super().__init__(master, fg_color="transparent")
        self.command = command
        self.value = values[0]
        self.counts: dict[str, int] = {}
        self.buttons: dict[str, ctk.CTkButton] = {}
        for v in values:
            b = ctk.CTkButton(
                self,
                text=v,
                height=30,
                corner_radius=15,
                border_width=1,
                font=font("body"),
                command=lambda val=v: self._click(val),
            )
            b.pack(side="left", padx=(0, SPACE["s"]))
            self.buttons[v] = b
        self._paint()

    def _click(self, value: str) -> None:
        self.set(value)
        if self.command:
            self.command(value)

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value
        self._paint()

    def set_counts(self, counts: dict[str, int]) -> None:
        self.counts = counts
        self._paint()

    def _paint(self) -> None:
        for v, b in self.buttons.items():
            active = v == self.value
            n = self.counts.get(v)
            b.configure(
                text=f"{v}  {n}" if n is not None else v,
                fg_color=T("accent_soft") if active else "transparent",
                border_color=T("accent") if active else T("border"),
                text_color=T("accent") if active else T("text2"),
                hover_color=T("surface2"),
            )


# ------------------------------------------------------------------ navegación
class NavRail(ctk.CTkFrame):
    """Barra de navegación lateral con icono + texto y barra de acento en el elemento activo."""

    def __init__(self, master: Any, items: list[tuple[str, str, str]], on_select: Callable[[str], None]) -> None:
        super().__init__(master, width=200, corner_radius=0, fg_color=T("surface"), border_width=0)
        self.on_select = on_select
        self.rows: dict[str, tuple[ctk.CTkFrame, ctk.CTkFrame, ctk.CTkButton]] = {}
        self.active = ""
        self.top = ctk.CTkFrame(self, fg_color="transparent")
        self.top.pack(fill="x", padx=SPACE["l"], pady=(SPACE["l"], SPACE["xl"]))
        for key, label, icon in items:
            row = ctk.CTkFrame(self, fg_color="transparent", height=40)
            row.pack(fill="x", padx=SPACE["s"], pady=2)
            bar = ctk.CTkFrame(row, width=3, height=22, corner_radius=2, fg_color="transparent")
            bar.pack(side="left", padx=(0, SPACE["xs"]))
            btn = ctk.CTkButton(
                row,
                text=f"{glyph(icon)}    {label}",
                anchor="w",
                height=38,
                corner_radius=RADIUS["control"],
                fg_color="transparent",
                hover_color=T("surface2"),
                text_color=T("text2"),
                font=font("body"),
                command=lambda k=key: self.on_select(k),
            )
            btn.pack(side="left", fill="x", expand=True)
            self.rows[key] = (row, bar, btn)
        self.bottom = ctk.CTkFrame(self, fg_color="transparent")
        self.bottom.pack(side="bottom", fill="x", padx=SPACE["l"], pady=SPACE["l"])

    def set_active(self, key: str) -> None:
        self.active = key
        for k, (_row, bar, btn) in self.rows.items():
            on = k == key
            bar.configure(fg_color=T("accent") if on else "transparent")
            btn.configure(
                fg_color=T("surface2") if on else "transparent",
                text_color=T("text") if on else T("text2"),
                font=font("body_bold") if on else font("body"),
            )

    def set_label(self, key: str, text: str) -> None:
        btn = self.rows[key][2]
        icon = btn.cget("text").split("    ")[0]
        btn.configure(text=f"{icon}    {text}")


# ------------------------------------------------------------------ tarjetas
def card(master: Any, title: str | None = None, **kw: Any) -> ctk.CTkFrame:
    frame = ctk.CTkFrame(
        master, fg_color=T("surface"), corner_radius=RADIUS["card"], border_width=1, border_color=T("border"), **kw
    )
    if title:
        ctk.CTkLabel(frame, text=title, font=font("subtitle"), text_color=T("text")).pack(
            anchor="w", padx=SPACE["l"], pady=(SPACE["l"], 0)
        )
    return frame


class StatCard(ctk.CTkFrame):
    """KPI: icono de estado, número grande, etiqueta y tendencia frente al análisis anterior."""

    def __init__(self, master: Any, title: str, hint: str, token: str, icon: str) -> None:
        super().__init__(
            master, fg_color=T("surface"), corner_radius=RADIUS["card"], border_width=1, border_color=T("border")
        )
        self.token = token
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=SPACE["l"], pady=(SPACE["l"], 0))
        ctk.CTkLabel(top, text=glyph(icon), font=icon_font(18), text_color=T(token), width=22).pack(side="left")
        ctk.CTkLabel(top, text=title, font=font("caption_bold"), text_color=T("text2")).pack(
            side="left", padx=SPACE["s"]
        )
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=SPACE["l"], pady=(SPACE["xs"], 0))
        self.value = ctk.CTkLabel(row, text="0", font=font("display"), text_color=T("text"))
        self.value.pack(side="left")
        self.delta = ctk.CTkLabel(row, text="", font=font("caption_bold"), text_color=T("text2"))
        self.delta.pack(side="left", padx=(SPACE["s"], 0), pady=(SPACE["s"], 0))
        self.hint = ctk.CTkLabel(self, text=hint, font=font("caption"), text_color=T("text2"))
        self.hint.pack(anchor="w", padx=SPACE["l"], pady=(0, SPACE["l"]))

    def set(self, value: str | int, delta: int | None = None, hint: str | None = None) -> None:
        self.value.configure(text=str(value))
        if delta is None or delta == 0:
            self.delta.configure(text="" if delta is None else "= igual", text_color=T("text2"))
        else:
            worse = delta > 0 and self.token in ("danger", "warning", "info")
            self.delta.configure(
                text=f"{'▲' if delta > 0 else '▼'} {abs(delta)}", text_color=T("danger" if worse else "success")
            )
        if hint is not None:
            self.hint.configure(text=hint)


# ------------------------------------------------------------------ gráficos
class _ChartBase(tk.Canvas):
    def __init__(self, master: tk.Misc, height: int = 200) -> None:
        super().__init__(master, highlightthickness=0, height=height, bd=0)
        self.bind("<Configure>", lambda _e: self.redraw())

    def redraw(self) -> None:  # pragma: no cover - lo implementan las subclases
        raise NotImplementedError

    def _prepare(self) -> tuple[int, int]:
        self.delete("all")
        self.configure(bg=c("surface"))
        return self.winfo_width(), self.winfo_height()

    def _empty(self, text: str) -> None:
        self.create_text(
            self.winfo_width() / 2, self.winfo_height() / 2, text=text, fill=c("text2"), font=tk_font("body")
        )


class DonutChart(_ChartBase):
    def __init__(self, master: tk.Misc, height: int = 200) -> None:
        super().__init__(master, height)
        self.items: list[tuple[str, int, str]] = []
        self.center = ("", "")

    def set(self, items: list[tuple[str, int, str]], center: str, subtitle: str) -> None:
        """items: (etiqueta, valor, token de color)."""
        self.items, self.center = items, (center, subtitle)
        self.redraw()

    def redraw(self) -> None:
        w, h = self._prepare()
        if w < 50:
            return
        total = sum(v for _, v, _ in self.items)
        size = min(h - 24, w * 0.45)
        x0, y0 = 12, (h - size) / 2
        box = (x0, y0, x0 + size, y0 + size)
        thick = max(12, size * 0.13)
        self.create_oval(*box, outline=c("surface2"), width=thick)
        start = 90.0
        for _, value, token in self.items:
            if value <= 0 or not total:
                continue
            extent = -360.0 * value / total
            if abs(extent) >= 359.99:
                self.create_oval(*box, outline=c(token), width=thick)
            else:
                self.create_arc(*box, start=start, extent=extent, style="arc", outline=c(token), width=thick)
            start += extent
        cx, cy = x0 + size / 2, y0 + size / 2
        self.create_text(cx, cy - 6, text=self.center[0], fill=c("text"), font=(ui_family(), int(size / 6), "bold"))
        self.create_text(cx, cy + size / 7, text=self.center[1], fill=c("text2"), font=tk_font("caption"))
        lx, ly = x0 + size + 24, h / 2 - 18 * len(self.items)
        for label, value, token in self.items:
            pct = f"{100 * value / total:.0f}%" if total else "—"
            self.create_oval(lx, ly + 5, lx + 9, ly + 14, fill=c(token), outline="")
            self.create_text(lx + 16, ly + 9, text=label, anchor="w", fill=c("text"), font=tk_font("body"))
            self.create_text(
                lx + 16, ly + 25, text=f"{value} · {pct}", anchor="w", fill=c("text2"), font=tk_font("caption")
            )
            ly += 38


class BarChart(_ChartBase):
    def __init__(self, master: tk.Misc, height: int = 200, limit: int = 6, empty: str = "Sin datos") -> None:
        super().__init__(master, height)
        self.items: list[tuple[str, float, str, str]] = []
        self.limit, self.empty_text = limit, empty

    def set(self, items: list[tuple[str, float, str, str]]) -> None:
        """items: (etiqueta, valor, token de color, texto del valor)."""
        self.items = items[: self.limit]
        self.redraw()

    def _fit(self, text: str, width: float) -> str:
        f = tkfont.Font(family=ui_family(), size=tk_font("body")[1])
        if f.measure(text) <= width:
            return text
        while text and f.measure(text + "…") > width:
            text = text[:-1]
        return text + "…"

    def redraw(self) -> None:
        w, h = self._prepare()
        if w < 50:
            return
        if not self.items:
            self._empty(self.empty_text)
            return
        label_w = min(240, w * 0.45)
        row_h = min(32, (h - 8) / max(len(self.items), 1))
        peak = max((v for _, v, _, _ in self.items), default=1) or 1
        bar_max = w - label_w - 56
        y = 4
        for label, value, token, text in self.items:
            self.create_text(
                label_w - 12,
                y + row_h / 2,
                text=self._fit(label, label_w - 16),
                anchor="e",
                fill=c("text"),
                font=tk_font("body"),
            )
            bw = max(4, bar_max * value / peak)
            yy0, yy1 = y + row_h / 2 - 5, y + row_h / 2 + 5
            self.create_rectangle(label_w, yy0, label_w + bar_max, yy1, fill=c("surface2"), outline="")
            self.create_rectangle(label_w, yy0, label_w + bw, yy1, fill=c(token), outline="")
            self.create_text(
                label_w + bar_max + 10, y + row_h / 2, text=text, anchor="w", fill=c("text2"), font=tk_font("caption")
            )
            y += row_h


class ScoreGauge(_ChartBase):
    def __init__(self, master: tk.Misc, height: int = 200) -> None:
        super().__init__(master, height)
        self.score, self.caption, self.token = 0, "", "text2"

    def set(self, score: int, caption: str, token: str) -> None:
        self.score, self.caption, self.token = score, caption, token
        self.redraw()

    def redraw(self) -> None:
        w, h = self._prepare()
        if w < 50:
            return
        r = min(w / 2 - 24, h - 48)
        cx, cy = w / 2, h - 36
        box = (cx - r, cy - r, cx + r, cy + r)
        thick = max(10, r * 0.14)
        self.create_arc(*box, start=0, extent=180, style="arc", outline=c("surface2"), width=thick)
        if self.score:
            self.create_arc(
                *box, start=180, extent=-180 * self.score / 100, style="arc", outline=c(self.token), width=thick
            )
        for mark in (30, 70):
            ang = math.radians(180 - 180 * mark / 100)
            x1, y1 = cx + (r - thick) * math.cos(ang), cy - (r - thick) * math.sin(ang)
            x2, y2 = cx + (r + thick / 2) * math.cos(ang), cy - (r + thick / 2) * math.sin(ang)
            self.create_line(x1, y1, x2, y2, fill=c("text2"), dash=(2, 2))
        self.create_text(
            cx, cy - r * 0.32, text=str(self.score), fill=c("text"), font=(ui_family(), int(r / 2.8), "bold")
        )
        self.create_text(cx, cy + 14, text=self.caption, fill=c(self.token), font=tk_font("caption_bold"))


# ------------------------------------------------------------------ notificaciones
def toast(
    root: ctk.CTk,
    text: str,
    token: str = "accent",
    ms: int = 3200,
    action: tuple[str, Callable[[], None]] | None = None,
) -> ctk.CTkFrame:
    """Aviso flotante abajo a la derecha. Con ``action`` muestra un botón (p. ej. «Deshacer»)."""
    for w in root.place_slaves():
        if getattr(w, "_is_toast", False):
            w.destroy()
    frame = ctk.CTkFrame(
        root, fg_color=T("surface2"), corner_radius=RADIUS["card"], border_width=1, border_color=T("border")
    )
    frame._is_toast = True  # type: ignore[attr-defined]
    ctk.CTkFrame(frame, width=4, corner_radius=2, fg_color=T(token)).pack(
        side="left", fill="y", padx=(SPACE["s"], 0), pady=SPACE["s"]
    )
    ctk.CTkLabel(frame, text=text, font=font("body"), text_color=T("text")).pack(
        side="left", padx=SPACE["m"], pady=SPACE["m"]
    )
    if action:
        label, cb = action

        def run() -> None:
            frame.destroy()
            cb()

        ghost_button(frame, label, run, width=90).pack(side="left", padx=(0, SPACE["s"]))
    frame.place(relx=1.0, rely=1.0, x=-SPACE["xl"], y=-48, anchor="se")
    frame.lift()
    root.after(ms, lambda: frame.winfo_exists() and frame.destroy())
    return frame


def themed_menu(master: tk.Misc) -> tk.Menu:
    return tk.Menu(
        master,
        tearoff=0,
        bg=c("surface2"),
        fg=c("text"),
        activebackground=c("accent"),
        activeforeground="#FFFFFF",
        bd=1,
        relief="solid",
        font=tk_font("body"),
    )


# ------------------------------------------------------------------ diálogos
class Modal(ctk.CTkToplevel):
    def __init__(self, master: ctk.CTk, title: str, size: str) -> None:
        super().__init__(master)
        self.title(title)
        self.geometry(size)
        self.resizable(False, False)
        self.transient(master)
        self.configure(fg_color=T("bg"))
        self.after(60, self._grab)
        self.bind("<Escape>", lambda _e: self.destroy())

    def _grab(self) -> None:
        try:
            self.grab_set()
            self.focus_force()
        except tk.TclError:
            pass


class SecretDialog(Modal):
    """Pide la API key sin mostrarla en claro."""

    def __init__(
        self,
        master: ctk.CTk,
        current: str,
        service: str = "VirusTotal",
        url: str = "https://www.virustotal.com/gui/my-apikey",
        label: str = "API key",
    ) -> None:
        super().__init__(master, f"Clave de {service}", "500x250")
        self.value: str | None = None
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=SPACE["xl"], pady=SPACE["xl"])
        ctk.CTkLabel(body, text=f"{label} de {service}", font=font("subtitle")).pack(anchor="w")
        ctk.CTkLabel(
            body,
            text="Se guarda solo en el archivo .env de tu carpeta de configuración.",
            font=font("caption"),
            text_color=T("text2"),
        ).pack(anchor="w", pady=(SPACE["xs"], SPACE["m"]))
        row = ctk.CTkFrame(body, fg_color="transparent")
        row.pack(fill="x")
        self.entry = ctk.CTkEntry(
            row, show="•", height=CONTROL_H, corner_radius=RADIUS["control"], placeholder_text="Pega aquí tu clave"
        )
        self.entry.pack(side="left", fill="x", expand=True)
        self.eye = icon_button(row, "search", self._toggle, "Mostrar u ocultar")
        self.eye.configure(text="👁")
        self.eye.pack(side="left", padx=(SPACE["s"], 0))
        if current and current != PLACEHOLDER_KEY:
            self.entry.insert(0, current)
        actions = ctk.CTkFrame(body, fg_color="transparent")
        actions.pack(fill="x", side="bottom")
        ghost_button(actions, "Obtener clave gratis ↗", lambda: webbrowser.open(url)).pack(side="left")
        primary_button(actions, "Guardar", self._ok, width=110).pack(side="right")
        secondary_button(actions, "Cancelar", self.destroy, width=110).pack(side="right", padx=SPACE["s"])
        self.entry.bind("<Return>", lambda _e: self._ok())
        self._shown = False

    def _toggle(self) -> None:
        self._shown = not self._shown
        self.entry.configure(show="" if self._shown else "•")

    def _ok(self) -> None:
        self.value = self.entry.get().strip()
        self.destroy()


class AboutDialog(Modal):
    def __init__(self, master: ctk.CTk) -> None:
        super().__init__(master, "Acerca de win11-triage", "460x420")
        logo = load_logo(88)
        if logo:
            ctk.CTkLabel(self, text="", image=logo).pack(pady=(SPACE["xxl"], SPACE["s"]))
        ctk.CTkLabel(self, text="win11-triage", font=font("title")).pack()
        ctk.CTkLabel(self, text=f"Versión {__version__}", font=font("caption"), text_color=T("text2")).pack()
        ctk.CTkLabel(
            self,
            text="Triaje defensivo de Windows 11: persistencia, procesos, red,\n"
            "eventos, análisis estático, YARA y VirusTotal.\n\n"
            "Solo lectura: nunca borra, termina ni sube ficheros.",
            font=font("body"),
            justify="center",
        ).pack(pady=SPACE["l"])
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack()
        secondary_button(row, "Repositorio", lambda: webbrowser.open(REPO_URL), icon="open", width=140).pack(
            side="left", padx=SPACE["xs"]
        )
        secondary_button(
            row, "MITRE ATT&CK", lambda: webbrowser.open("https://attack.mitre.org/"), icon="open", width=140
        ).pack(side="left", padx=SPACE["xs"])
        ctk.CTkLabel(self, text=f"{__copyright__} · Licencia MIT", font=font("caption"), text_color=T("text2")).pack(
            pady=(SPACE["l"], 0)
        )
        primary_button(self, "Cerrar", self.destroy, width=120).pack(pady=SPACE["l"])
