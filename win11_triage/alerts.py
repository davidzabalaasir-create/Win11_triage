"""Alertas e integraciones: notificación de Windows, webhooks (Slack, Teams, JSON), Splunk HEC y JSONL.

- ``select_alertable``: con ``only_new`` solo alerta de lo nuevo o lo que ha empeorado respecto al
  análisis anterior (ideal para análisis programados: sin ruido si nada cambia).
- ``notify_toast``: notificación nativa de Windows 10/11 mediante WinRT desde PowerShell.
- ``send_webhook``: detecta el destino por la URL. Slack (hooks.slack.com), Teams (webhook.office.com,
  *.logic.azure.com, Power Automate), Splunk HEC (/services/collector, token en SPLUNK_HEC_TOKEN)
  o JSON genérico (Wazuh, n8n, tu propio servidor).
- ``write_jsonl``: un hallazgo por línea con campos de estilo ECS, para Wazuh/Filebeat/Elastic.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from collections.abc import Iterable
from datetime import timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from . import __version__
from .models import Finding, Status
from .report import TriageResult, diff_results, why

APP_ID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"


# ------------------------------------------------------------------ qué alertar
def select_alertable(
    current: TriageResult, previous: TriageResult | None = None, only_new: bool = False, min_score: int = 30
) -> list[Finding]:
    """Hallazgos que merecen alerta (rojo o amarillo con score ≥ min_score)."""
    relevant = [f for f in current.findings if f.status == Status.DETECTED or f.score >= min_score]
    if not only_new or previous is None:
        return sorted(relevant, key=lambda f: -f.score)
    diff = diff_results(previous, current)
    changed = {f.key for f in diff.new} | {f.key for f, _ in diff.worse}
    return sorted((f for f in relevant if f.key in changed), key=lambda f: -f.score)


def summary_text(res: TriageResult, items: list[Finding], only_new: bool) -> tuple[str, str]:
    c = res.counts()
    head = f"{res.host}: {c[Status.DETECTED]} detectados · {c[Status.UNKNOWN]} a revisar"
    if not items:
        return head, "Sin novedades desde el análisis anterior." if only_new else "Nada que alertar."
    label = "nuevos o peores" if only_new else "más graves"
    top = "; ".join(f"{f.name} ({f.score})" for f in items[:3])
    more = f" y {len(items) - 3} más" if len(items) > 3 else ""
    return head, f"{len(items)} {label}: {top}{more}"


# ------------------------------------------------------------------ notificación de Windows
def toast_script(title: str, body: str) -> str:
    def esc(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))[:250]

    xml = f"<toast><visual><binding template='ToastGeneric'><text>{esc(title)}</text><text>{esc(body)}</text></binding></visual></toast>"
    return (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;"
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null;"
        "$x = New-Object Windows.Data.Xml.Dom.XmlDocument;"
        f"$x.LoadXml(@'\n{xml}\n'@);"
        f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{APP_ID}')"
        ".Show([Windows.UI.Notifications.ToastNotification]::new($x))"
    )


def notify_toast(title: str, body: str) -> bool:
    """Muestra una notificación de Windows. Devuelve False fuera de Windows o si falla."""
    if sys.platform != "win32":
        return False
    # -EncodedCommand evita problemas de comillas (UTF-16LE en base64, como espera PowerShell)
    encoded = base64.b64encode(toast_script(title, body).encode("utf-16-le")).decode()
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


# ------------------------------------------------------------------ webhooks
def webhook_kind(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if host == "hooks.slack.com":
        return "slack"
    if host.endswith(("webhook.office.com", ".logic.azure.com", ".powerplatform.com")) or "powerautomate" in host:
        return "teams"
    if "/services/collector" in urlparse(url).path:
        return "splunk"
    return "json"


def finding_event(f: Finding, res: TriageResult) -> dict[str, Any]:
    """Hallazgo con campos de estilo ECS (Elastic Common Schema)."""
    return {
        "@timestamp": (res.finished or res.started).astimezone(timezone.utc).isoformat(timespec="seconds"),
        "event": {"kind": "alert", "module": "win11-triage", "dataset": f"win11_triage.{f.source}"},
        "host": {"name": res.host},
        "user": {"name": res.user},
        "rule": {"name": f.name, "category": f.category},
        "threat": {"technique": {"id": f.attack}},
        "file": {"path": f.path, "hash": {"sha256": f.sha256}} if f.path else {},
        "process": {"command_line": f.cmdline, "pid": f.pid} if f.cmdline or f.pid else {},
        "win11_triage": {
            "key": f.key,
            "status": f.status.value,
            "score": f.score,
            "source": f.source,
            "why": why(f, 5),
            "location": f.location,
            "remote": [c.remote for c in f.connections][:10],
            "vt": f.vt_summary,
        },
    }


def build_payload(kind: str, res: TriageResult, items: list[Finding], only_new: bool) -> Any:
    title, body = summary_text(res, items, only_new)
    if kind == "slack":
        lines = "\n".join(f"• *{f.score}* {f.name} — {why(f, 2)}" for f in items[:10]) or body
        return {
            "text": f"win11-triage · {title}",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"win11-triage · {res.host}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*\n{body}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": lines[:2900]}},
            ],
        }
    if kind == "teams":
        facts = [{"title": str(f.score), "value": f"{f.name} — {why(f, 2)}"} for f in items[:10]]
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "Large",
                                "weight": "Bolder",
                                "text": f"win11-triage · {res.host}",
                            },
                            {"type": "TextBlock", "wrap": True, "text": f"{title}. {body}"},
                            {"type": "FactSet", "facts": facts},
                        ],
                    },
                }
            ],
        }
    if kind == "splunk":
        epoch = (res.finished or res.started).timestamp()
        return [
            {"time": epoch, "host": res.host, "sourcetype": "win11_triage", "event": finding_event(f, res)}
            for f in items
        ]
    return {
        "tool": "win11-triage",
        "version": __version__,
        "host": res.host,
        "user": res.user,
        "started": res.started.isoformat(timespec="seconds"),
        "summary": {s.value: n for s, n in res.counts().items()},
        "title": title,
        "message": body,
        "only_new": only_new,
        "findings": [finding_event(f, res) for f in items],
    }


def send_webhook(
    url: str,
    res: TriageResult,
    items: list[Finding],
    only_new: bool = False,
    session: requests.Session | None = None,
) -> str:
    """Envía la alerta. Devuelve el tipo de destino. Lanza requests.RequestException si falla."""
    kind = webhook_kind(url)
    payload = build_payload(kind, res, items, only_new)
    headers = {"User-Agent": f"win11-triage/{__version__}"}
    if kind == "splunk":
        token = os.environ.get("SPLUNK_HEC_TOKEN", "").strip()
        if not token:
            raise requests.RequestException("SPLUNK_HEC_TOKEN no configurado para Splunk HEC")
        headers["Authorization"] = f"Splunk {token}"
        data = "\n".join(json.dumps(e, ensure_ascii=False) for e in payload)  # HEC acepta eventos concatenados
        r = (session or requests).post(url, data=data.encode("utf-8"), headers=headers, timeout=20)
    else:
        r = (session or requests).post(url, json=payload, headers=headers, timeout=20)
    r.raise_for_status()
    return kind


def write_jsonl(path: Path, res: TriageResult, items: Iterable[Finding]) -> int:
    """Añade un hallazgo por línea (append), para que Wazuh/Filebeat lo lean como un log."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("a", encoding="utf-8") as fh:
        for f in items:
            fh.write(json.dumps(finding_event(f, res), ensure_ascii=False) + "\n")
            n += 1
    return n
