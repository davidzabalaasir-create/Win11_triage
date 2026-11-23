"""Resumen ejecutivo en PDF de una página: veredicto, cifras, lo más grave y qué hacer.

Pensado para quien no es técnico (un responsable, un cliente): sin rutas largas ni tablas de señales.
Usa reportlab; con Segoe UI (Windows) o DejaVu Sans si están, para tener todos los caracteres.
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from . import __copyright__, __version__, playbook
from .models import Status
from .report import SOURCE_LABEL, TriageResult, attack_summary, sort_findings, why

ASSETS = Path(__file__).resolve().parent / "assets"
FONT_CANDIDATES = (
    ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
)
COLOR = {Status.DETECTED: "#D92D20", Status.UNKNOWN: "#B54708", Status.CLEAN: "#067647"}
VERDICT = {
    Status.DETECTED: ("Riesgo alto", "Hay elementos con indicios claros de actividad maliciosa. Actúa hoy."),
    Status.UNKNOWN: ("Revisar", "No hay detecciones claras, pero sí elementos que conviene comprobar."),
    Status.CLEAN: ("Sin indicios", "No se han encontrado elementos sospechosos en los módulos ejecutados."),
}


def _fonts() -> tuple[str, str]:
    for regular, bold in FONT_CANDIDATES:
        if Path(regular).exists() and Path(bold).exists():
            try:
                pdfmetrics.registerFont(TTFont("W11", regular))
                pdfmetrics.registerFont(TTFont("W11-Bold", bold))
                return "W11", "W11-Bold"
            except Exception:  # fuente corrupta o no TrueType: se usa la estándar
                continue
    return "Helvetica", "Helvetica-Bold"


def _safe(text: str, unicode_ok: bool) -> str:
    text = escape(text)
    return text if unicode_ok else text.replace("→", "->").replace("…", "...").replace("≥", ">=")


def render_pdf(r: TriageResult, out: Path) -> Path:
    regular, bold = _fonts()
    uni = regular == "W11"

    def P(text: str, size: float = 9.5, font: str = regular, color: str = "#1A1F26", lead: float = 1.3) -> Paragraph:
        st = ParagraphStyle("p", fontName=font, fontSize=size, leading=size * lead, textColor=color, alignment=TA_LEFT)
        return Paragraph(_safe(text, uni), st)

    counts = r.counts()
    overall = Status.DETECTED if counts[Status.DETECTED] else Status.UNKNOWN if counts[Status.UNKNOWN] else Status.CLEAN
    label, sentence = VERDICT[overall]
    W = A4[0] - 30 * mm
    story: list = []

    # cabecera
    logo = Image(str(ASSETS / "icon_64.png"), 12 * mm, 12 * mm) if (ASSETS / "icon_64.png").exists() else ""
    head = Table(
        [
            [
                logo,
                [P("Informe ejecutivo de seguridad", 16, bold), P(f"win11-triage {__version__}", 8.5, color="#5B6573")],
                [
                    P(f"Equipo: {r.host}", 9, bold),
                    P(f"{r.started:%d/%m/%Y %H:%M}" + (" · demostración" if r.dry_run else ""), 8.5, color="#5B6573"),
                ],
            ]
        ],
        colWidths=[16 * mm, W - 66 * mm, 50 * mm],
    )
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story += [head, Spacer(1, 6 * mm)]

    # veredicto
    max_score = max((f.score for f in r.findings), default=0)
    verdict = Table(
        [[P(label, 17, bold, "#FFFFFF"), P(sentence, 10.5, regular, "#FFFFFF")]],
        colWidths=[52 * mm, W - 52 * mm],
    )
    verdict.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(COLOR[overall])),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story += [verdict, Spacer(1, 5 * mm)]

    # cifras
    def stat(n: object, text: str, color: str = "#1A1F26") -> list:
        return [P(str(n), 18, bold, color), P(text, 8.5, color="#5B6573")]

    reviewed = sum(1 for f in r.findings if (r.review_of(f) or {}).get("state", "Pendiente") != "Pendiente")
    stats = Table(
        [
            [
                stat(counts[Status.DETECTED], "detectados", COLOR[Status.DETECTED]),
                stat(counts[Status.UNKNOWN], "a revisar", COLOR[Status.UNKNOWN]),
                stat(counts[Status.CLEAN], "limpios", COLOR[Status.CLEAN]),
                stat(max_score, "puntuación máxima (0-100)"),
                stat(f"{reviewed}/{len(r.findings)}", "revisados por el analista"),
            ]
        ],
        colWidths=[W / 5] * 5,
    )
    stats.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#DDE1E7")),
                ("LINEAFTER", (0, 0), (-2, -1), 0.6, colors.HexColor("#DDE1E7")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story += [stats, Spacer(1, 6 * mm)]

    # lo más grave
    top = [f for f in sort_findings(r.findings) if f.status != Status.CLEAN][:5]
    if top:
        story += [P("Lo más importante", 12, bold), Spacer(1, 2 * mm)]
        rows = [[P("Score", 8.5, bold), P("Elemento", 8.5, bold), P("Qué es y qué hacer", 8.5, bold)]]
        for f in top:
            adv = playbook.advice_for(f)
            rows.append(
                [
                    P(str(f.score), 11, bold, COLOR[f.status]),
                    [P(f.name[:60], 9, bold), P(SOURCE_LABEL.get(f.source, f.source), 8, color="#5B6573")],
                    [P(adv.summary, 8.5), P("→ " + adv.steps[0], 8.5, color="#2563EB") if adv.steps else ""],
                ]
            )
        t = Table(rows, colWidths=[16 * mm, 55 * mm, W - 71 * mm], repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDE1E7")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story += [t, Spacer(1, 5 * mm)]

    # técnicas ATT&CK y alcance
    techniques = attack_summary(r.findings)[:6]
    if techniques:
        text = " · ".join(f"{tid} {name} ({n})" for tid, name, n in techniques)
        story += [P("Técnicas de ataque observadas (MITRE ATT&CK)", 11, bold), P(text, 8.5), Spacer(1, 4 * mm)]
    scope = ", ".join(r.modules) or "ninguno"
    notes = f"Módulos ejecutados: {scope}. Elementos ignorados por lista blanca: {r.whitelisted}."
    if r.errors:
        notes += f" Avisos durante el análisis: {len(r.errors)} (ver informe completo)."
    story += [P("Alcance", 11, bold), P(notes, 8.5, color="#5B6573")]
    if top:
        story += [Spacer(1, 3 * mm), P(f"Motivo principal del primer elemento: {why(top[0], 3)}", 8, color="#5B6573")]

    def footer(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont(regular, 7.5)
        canvas.setFillColor(colors.HexColor("#5B6573"))
        canvas.drawString(
            15 * mm, 10 * mm, _safe(f"win11-triage {__version__} · {__copyright__}", uni).replace("&amp;", "&")
        )
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, "Informe técnico completo: HTML/Markdown/JSON")
        canvas.restoreState()

    out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=14 * mm,
        bottomMargin=16 * mm,
        title=f"Informe ejecutivo · {r.host}",
        author="win11-triage",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return out
