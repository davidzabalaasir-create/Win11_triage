"""Componentes reutilizables: tarjetas, gráficos en Canvas, diálogos y notificaciones."""

from __future__ import annotations

import math
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from collections.abc import Callable

import customtkinter as ctk
from PIL import Image

from .. import __version__
from ..engine import PLACEHOLDER_KEY
from .theme import ACCENT, BORDER, CARD, CYAN, ICON_PNG, MUTED, PANEL, TEXT

REPO_URL = "https://github.com/davidzabalaasir-create/Win11_triage"


def load_logo(size: int) -> ctk.CTkImage | None:
    try:
        img = Image.open(ICON_PNG)
    except OSError:
        return None
    return ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))


def dark_menu(master: tk.Misc) -> tk.Menu:
    return tk.Menu(
        master,
        tearoff=0,
        bg=CARD,
        fg=TEXT,
        activebackground=ACCENT,
        activeforeground="#ffffff",
        bd=0,
        relief="flat",
        font=("Segoe UI", 10),
    )


# ----------------------------------------------------------------- tarjetas
class StatCard(ctk.CTkFrame):
    def __init__(self, master: tk.Misc, title: str, hint: str, color: str) -> None:
        super().__init__(master, fg_color=CARD, corner_radius=12, border_width=1, border_color=BORDER)
        ctk.CTkFrame(self, fg_color=color, height=4, corner_radius=2).pack(fill="x", padx=14, pady=(12, 0))
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(4, 0))
        self.value = ctk.CTkLabel(row, text="0", font=ctk.CTkFont(size=30, weight="bold"), text_color=color)
        self.value.pack(side="left")
        self.delta = ctk.CTkLabel(row, text="", text_color=MUTED, font=ctk.CTkFont(size=12))
        self.delta.pack(side="left", padx=(8, 0), pady=(10, 0))
        ctk.CTkLabel(self, text=title, font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=16)
        self.hint = ctk.CTkLabel(self, text=hint, text_color=MUTED, font=ctk.CTkFont(size=11))
        self.hint.pack(anchor="w", padx=16, pady=(0, 12))

    def set(self, value: str | int, delta: str = "", hint: str | None = None) -> None:
        self.value.configure(text=str(value))
        self.delta.configure(text=delta)
        if hint is not None:
            self.hint.configure(text=hint)


# ----------------------------------------------------------------- gráficos
class _ChartBase(tk.Canvas):
    def __init__(self, master: tk.Misc, height: int = 220) -> None:
        super().__init__(master, bg=CARD, highlightthickness=0, height=height)
        self.bind("<Configure>", lambda _e: self.redraw())

    def redraw(self) -> None:  # pragma: no cover - lo implementan las subclases
        raise NotImplementedError

    def _empty(self, text: str) -> None:
        self.create_text(self.winfo_width() / 2, self.winfo_height() / 2, text=text, fill=MUTED, font=("Segoe UI", 11))


class DonutChart(_ChartBase):
    """Anillo de proporciones con leyenda a la derecha y total en el centro."""

    def __init__(self, master: tk.Misc, height: int = 220) -> None:
        super().__init__(master, height)
        self.items: list[tuple[str, int, str]] = []
        self.center = ("", "")

    def set(self, items: list[tuple[str, int, str]], center: str, subtitle: str) -> None:
        self.items, self.center = items, (center, subtitle)
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 50:
            return
        total = sum(v for _, v, _ in self.items)
        size = min(h - 30, w * 0.45)
        x0, y0 = 20, (h - size) / 2
        box = (x0, y0, x0 + size, y0 + size)
        thick = max(14, size * 0.16)
        if total == 0:
            self.create_oval(*box, outline=BORDER, width=thick)
        else:
            start = 90.0
            for _, value, color in self.items:
                if value <= 0:
                    continue
                extent = -360.0 * value / total
                if abs(extent) >= 359.99:
                    self.create_oval(*box, outline=color, width=thick)
                else:
                    self.create_arc(*box, start=start, extent=extent, style="arc", outline=color, width=thick)
                start += extent
        cx, cy = x0 + size / 2, y0 + size / 2
        self.create_text(cx, cy - 8, text=self.center[0], fill=TEXT, font=("Segoe UI", int(size / 6), "bold"))
        self.create_text(cx, cy + size / 7, text=self.center[1], fill=MUTED, font=("Segoe UI", 9))
        lx, ly = x0 + size + 28, h / 2 - 18 * len(self.items)
        for label, value, color in self.items:
            pct = f"{100 * value / total:.0f}%" if total else "—"
            self.create_oval(lx, ly + 5, lx + 10, ly + 15, fill=color, outline="")
            self.create_text(lx + 18, ly + 10, text=label, anchor="w", fill=TEXT, font=("Segoe UI", 10))
            self.create_text(lx + 18, ly + 26, text=f"{value} · {pct}", anchor="w", fill=MUTED, font=("Segoe UI", 9))
            ly += 36


class BarChart(_ChartBase):
    """Barras horizontales etiquetadas (máximo ``limit`` filas)."""

    def _fit(self, text: str, width: float) -> str:
        """Recorta el texto con «…» para que quepa en ``width`` píxeles con la fuente real."""
        font = tkfont.Font(family="Segoe UI", size=10)
        if font.measure(text) <= width:
            return text
        while text and font.measure(text + "…") > width:
            text = text[:-1]
        return text + "…"

    def __init__(self, master: tk.Misc, height: int = 220, limit: int = 7, empty: str = "Sin datos") -> None:
        super().__init__(master, height)
        self.items: list[tuple[str, float, str, str]] = []
        self.limit, self.empty_text = limit, empty

    def set(self, items: list[tuple[str, float, str, str]]) -> None:
        """items: (etiqueta, valor, color, texto del valor)."""
        self.items = items[: self.limit]
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 50:
            return
        if not self.items:
            self._empty(self.empty_text)
            return
        label_w = min(220, w * 0.42)
        row_h = min(30, (h - 16) / max(len(self.items), 1))
        peak = max((v for _, v, _, _ in self.items), default=1) or 1
        bar_max = w - label_w - 70
        y = 8
        for label, value, color, text in self.items:
            short = self._fit(label, label_w - 12)
            self.create_text(label_w - 8, y + row_h / 2, text=short, anchor="e", fill=TEXT, font=("Segoe UI", 10))
            bw = max(3, bar_max * value / peak)
            self.create_rectangle(label_w, y + 6, label_w + bar_max, y + row_h - 6, fill=PANEL, outline="")
            self.create_rectangle(label_w, y + 6, label_w + bw, y + row_h - 6, fill=color, outline="")
            self.create_text(
                label_w + bar_max + 8, y + row_h / 2, text=text, anchor="w", fill=MUTED, font=("Segoe UI", 10)
            )
            y += row_h


class ScoreGauge(_ChartBase):
    """Semicírculo 0–100 con la puntuación máxima del análisis."""

    def __init__(self, master: tk.Misc, height: int = 220) -> None:
        super().__init__(master, height)
        self.score, self.caption, self.color = 0, "", MUTED

    def set(self, score: int, caption: str, color: str) -> None:
        self.score, self.caption, self.color = score, caption, color
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 50:
            return
        r = min(w / 2 - 30, h - 60)
        cx, cy = w / 2, h - 45
        box = (cx - r, cy - r, cx + r, cy + r)
        thick = max(12, r * 0.18)
        self.create_arc(*box, start=0, extent=180, style="arc", outline=PANEL, width=thick)
        if self.score:
            self.create_arc(
                *box, start=180, extent=-180 * self.score / 100, style="arc", outline=self.color, width=thick
            )
        for mark in (30, 70):  # umbrales del veredicto
            ang = math.radians(180 - 180 * mark / 100)
            x1, y1 = cx + (r - thick) * math.cos(ang), cy - (r - thick) * math.sin(ang)
            x2, y2 = cx + (r + thick / 2) * math.cos(ang), cy - (r + thick / 2) * math.sin(ang)
            self.create_line(x1, y1, x2, y2, fill=MUTED, dash=(2, 2))
        self.create_text(
            cx, cy - r * 0.3, text=str(self.score), fill=self.color, font=("Segoe UI", int(r / 2.6), "bold")
        )
        self.create_text(cx, cy + 18, text=self.caption, fill=MUTED, font=("Segoe UI", 10))


# ----------------------------------------------------------------- notificaciones
def toast(root: ctk.CTk, text: str, color: str = ACCENT, ms: int = 2600) -> None:
    """Aviso flotante breve en la parte inferior de la ventana."""
    frame = ctk.CTkFrame(root, fg_color=CARD, corner_radius=10, border_width=1, border_color=color)
    ctk.CTkLabel(frame, text=text, text_color=TEXT).pack(padx=16, pady=8)
    frame.place(relx=1.0, rely=1.0, x=-24, y=-48, anchor="se")
    frame.lift()
    root.after(ms, frame.destroy)


# ----------------------------------------------------------------- diálogos
class _Modal(ctk.CTkToplevel):
    def __init__(self, master: ctk.CTk, title: str, size: str) -> None:
        super().__init__(master)
        self.title(title)
        self.geometry(size)
        self.resizable(False, False)
        self.transient(master)
        self.configure(fg_color=PANEL)
        self.after(60, self._grab)

    def _grab(self) -> None:
        try:
            self.grab_set()
            self.focus_force()
        except tk.TclError:
            pass


class SecretDialog(_Modal):
    """Pide la API key sin mostrarla en claro."""

    def __init__(self, master: ctk.CTk, current: str) -> None:
        super().__init__(master, "Clave de VirusTotal", "480x230")
        self.value: str | None = None
        ctk.CTkLabel(self, text="API key de VirusTotal", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=20, pady=(18, 2)
        )
        ctk.CTkLabel(
            self,
            text="Se guarda solo en el archivo .env de tu carpeta de configuración.\n"
            "Nunca se sube a GitHub (está en .gitignore).",
            text_color=MUTED,
            justify="left",
        ).pack(anchor="w", padx=20)
        self.entry = ctk.CTkEntry(self, show="•", width=440, placeholder_text="Pega aquí tu clave")
        self.entry.pack(padx=20, pady=14)
        if current and current != PLACEHOLDER_KEY:
            self.entry.insert(0, current)
        self.show = ctk.CTkCheckBox(self, text="Mostrar", command=self._toggle, width=20)
        self.show.pack(anchor="w", padx=20)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(10, 0))
        ctk.CTkButton(row, text="Guardar", width=110, command=self._ok).pack(side="right")
        ctk.CTkButton(row, text="Cancelar", width=110, fg_color=CARD, hover_color=BORDER, command=self.destroy).pack(
            side="right", padx=8
        )
        ctk.CTkButton(
            row,
            text="Obtener clave gratis",
            fg_color="transparent",
            text_color=CYAN,
            hover_color=CARD,
            command=lambda: webbrowser.open("https://www.virustotal.com/gui/my-apikey"),
        ).pack(side="left")
        self.entry.bind("<Return>", lambda _e: self._ok())

    def _toggle(self) -> None:
        self.entry.configure(show="" if self.show.get() else "•")

    def _ok(self) -> None:
        self.value = self.entry.get().strip()
        self.destroy()


class AboutDialog(_Modal):
    def __init__(self, master: ctk.CTk) -> None:
        super().__init__(master, "Acerca de win11-triage", "460x420")
        logo = load_logo(96)
        if logo:
            ctk.CTkLabel(self, text="", image=logo).pack(pady=(24, 6))
        ctk.CTkLabel(self, text="win11-triage", font=ctk.CTkFont(size=22, weight="bold")).pack()
        ctk.CTkLabel(self, text=f"Versión {__version__}", text_color=MUTED).pack()
        ctk.CTkLabel(
            self,
            text="Triaje defensivo de Windows 11: persistencia, procesos, red,\n"
            "eventos, análisis estático, YARA y VirusTotal.\n\n"
            "Solo lectura: nunca borra, mata ni sube ficheros.\n"
            "Es una herramienta de triaje: no sustituye a un antivirus.",
            justify="center",
        ).pack(pady=14)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(pady=4)
        links: list[tuple[str, Callable[[], object]]] = [
            ("Repositorio", lambda: webbrowser.open(REPO_URL)),
            ("MITRE ATT&CK", lambda: webbrowser.open("https://attack.mitre.org/")),
        ]
        for text, cmd in links:
            ctk.CTkButton(row, text=text, width=130, fg_color=CARD, hover_color=BORDER, command=cmd).pack(
                side="left", padx=6
            )
        ctk.CTkLabel(self, text="© 2026 David · Licencia MIT", text_color=MUTED, font=ctk.CTkFont(size=11)).pack(
            pady=(14, 0)
        )
        ctk.CTkButton(self, text="Cerrar", width=120, command=self.destroy).pack(pady=12)
