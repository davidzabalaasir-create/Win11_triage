"""Asistente de IA: responde preguntas sobre un análisis con herramientas de solo lectura.

Proveedor por defecto: **Groq** (gratuito, API compatible con OpenAI, modelo ``openai/gpt-oss-120b``).
Alternativa 100 % local: **Ollama** (``AI_PROVIDER=ollama``). Cualquier otro servicio compatible
con OpenAI funciona con ``AI_BASE_URL`` y ``AI_MODEL``.

Privacidad: el modelo nunca recibe ficheros ni el informe completo. Recibe un resumen y, cuando lo
pide, el detalle de un hallazgo concreto; el usuario de Windows y el nombre del equipo se sustituyen
por marcadores. El asistente no puede modificar nada: solo consulta datos del análisis.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import requests

from . import __version__, playbook
from .i18n import get_language, t
from .models import Finding, Status
from .report import SOURCE_LABEL, TriageResult, attack_summary, process_chains, sort_findings, why

PROVIDERS = {
    "groq": ("https://api.groq.com/openai/v1", "openai/gpt-oss-120b", "GROQ_API_KEY"),
    "ollama": ("http://localhost:11434/v1", "llama3.1", ""),
}
MAX_STEPS = 6  # rondas de herramientas por pregunta
MAX_HISTORY = 12  # mensajes de conversación que se conservan


def new_session() -> requests.Session:
    """Sesión HTTP del asistente (sustituible en pruebas)."""
    return requests.Session()


class AgentError(RuntimeError):
    pass


@dataclass
class AgentConfig:
    provider: str = "groq"
    base_url: str = ""
    model: str = ""
    api_key: str = ""

    @classmethod
    def from_env(cls) -> AgentConfig:
        provider = os.environ.get("AI_PROVIDER", "groq").strip().lower() or "groq"
        base, model, key_var = PROVIDERS.get(provider, PROVIDERS["groq"])
        return cls(
            provider=provider,
            base_url=os.environ.get("AI_BASE_URL", "").strip() or base,
            model=os.environ.get("AI_MODEL", "").strip() or model,
            api_key=os.environ.get(key_var or "AI_API_KEY", "").strip() or os.environ.get("AI_API_KEY", "").strip(),
        )

    @property
    def ready(self) -> bool:
        return bool(self.api_key) or self.provider == "ollama"


# ------------------------------------------------------------------ anonimización
class Redactor:
    """Sustituye el usuario de Windows y el nombre del equipo en todo lo que sale hacia el modelo."""

    def __init__(self, res: TriageResult) -> None:
        self.rules: list[tuple[re.Pattern[str], str]] = []
        text = "\n".join(f"{f.path} {f.cmdline} {f.location}" for f in res.findings)
        users = {res.user} | set(re.findall(r"\\Users\\([^\\\s\"]+)\\", text, re.IGNORECASE))
        for u in sorted(users - {"", "Public", "Default", "All Users"}, key=len, reverse=True):
            if len(u) >= 2:
                self.rules.append((re.compile(rf"\b{re.escape(u)}\b", re.IGNORECASE), "<usuario>"))
        if res.host:
            self.rules.append((re.compile(rf"\b{re.escape(res.host)}\b", re.IGNORECASE), "<equipo>"))

    def __call__(self, text: str) -> str:
        for rx, repl in self.rules:
            text = rx.sub(repl, text)
        return text


# ------------------------------------------------------------------ herramientas (solo lectura)
def _brief(i: int, f: Finding) -> dict[str, Any]:
    return {
        "id": i,
        "status": t(f.status.value),
        "score": f.score,
        "source": t(SOURCE_LABEL.get(f.source, f.source)),
        "name": f.name,
        "why": why(f, 3),
        "attack": f.attack[:5],
    }


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_findings",
            "description": "Lista hallazgos del análisis, del más grave al menos grave, con filtros opcionales.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["DETECTADO", "DESCONOCIDO", "LIMPIO"]},
                    "source": {
                        "type": "string",
                        "enum": ["autoruns", "sigcheck", "process", "event", "sigma", "browser"],
                    },
                    "min_score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "search": {"type": "string", "description": "Texto en nombre, ruta o técnica ATT&CK"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 30},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_finding",
            "description": "Detalle de un hallazgo por id: señales con peso y evidencia, ruta, línea de comandos, "
            "firma, VirusTotal, conexiones, revisión del analista y pasos recomendados.",
            "parameters": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "process_chain",
            "description": "Cadena padre → hijo de los procesos señalados (o de un PID concreto).",
            "parameters": {"type": "object", "properties": {"pid": {"type": "integer"}}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_allowlist",
            "description": "Propone la entrada de lista blanca para un hallazgo (no la aplica: el usuario decide).",
            "parameters": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]},
        },
    },
]


class Toolbox:
    def __init__(self, res: TriageResult, redact: Redactor) -> None:
        self.res = res
        self.redact = redact
        self.findings = sort_findings(res.findings)

    def call(self, name: str, args: dict[str, Any]) -> str:
        fn = getattr(self, f"tool_{name}", None)
        if fn is None:
            return json.dumps({"error": f"herramienta desconocida: {name}"})
        try:
            out = fn(**args)
        except (TypeError, ValueError, IndexError, KeyError) as e:
            out = {"error": str(e)}
        return self.redact(json.dumps(out, ensure_ascii=False))[:12000]

    def _get(self, id: int) -> Finding:
        if not 0 <= int(id) < len(self.findings):
            raise IndexError(f"id fuera de rango (0–{len(self.findings) - 1})")
        return self.findings[int(id)]

    def tool_list_findings(
        self,
        status: str | None = None,
        source: str | None = None,
        min_score: int | None = None,
        search: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        out = []
        for i, f in enumerate(self.findings):
            if status and f.status.value != status:
                continue
            if source and f.source != source:
                continue
            if min_score is not None and f.score < int(min_score):
                continue
            if search and search.lower() not in f"{f.name} {f.path} {' '.join(f.attack)}".lower():
                continue
            out.append(_brief(i, f))
        return {"total": len(out), "findings": out[: max(1, min(int(limit), 30))]}

    def tool_get_finding(self, id: int) -> dict[str, Any]:
        f = self._get(id)
        adv = playbook.advice_for(f)
        rv = self.res.review_of(f) or {}
        return {
            **_brief(int(id), f),
            "path": f.path,
            "command_line": f.cmdline[:600],
            "category": f.category,
            "location": f.location,
            "publisher": f.publisher,
            "signature": f.signature,
            "sha256": f.sha256,
            "created": f.created,
            "parent": f.parent,
            "virustotal": f.vt_summary,
            "connections": [f"{c.protocol} {c.remote} ({c.state})" for c in f.connections][:10],
            "signals": [
                {"title": t(s.title), "weight": s.weight, "attack": s.attack, "evidence": s.evidence[:200]}
                for s in f.unique_signals
            ],
            "analyst_review": {"state": rv.get("state", "Pendiente"), "note": rv.get("note", "")},
            "recommended_steps": list(adv.steps),
        }

    def tool_process_chain(self, pid: int | None = None) -> dict[str, Any]:
        chains = process_chains(self.res)
        if pid is not None:
            chains = [ch for ch in chains if any(p["pid"] == int(pid) for p in ch)]
        return {
            "chains": [
                [{"pid": p["pid"], "name": p["name"], "flagged": p.get("flagged", False), "score": p.get("score", 0)}
                 for p in ch]
                for ch in chains[:10]
            ]
        }  # fmt: skip

    def tool_suggest_allowlist(self, id: int) -> dict[str, Any]:
        f = self._get(id)
        if f.status == Status.DETECTED:
            warning = "No se recomienda: el elemento está DETECTADO. Confírmalo antes como falso positivo."
        else:
            warning = ""
        entry = {"hashes": [f.sha256]} if f.sha256 else {"paths": [f.path]}
        return {"whitelist_json_entry": entry, "warning": warning, "how": "Hallazgos → Más acciones → Ignorar"}


# ------------------------------------------------------------------ conversación
def summary_context(res: TriageResult) -> str:
    c = res.counts()
    top = [_brief(i, f) for i, f in enumerate(sort_findings(res.findings)) if f.status != Status.CLEAN][:8]
    data = {
        "scan": {
            "date": res.started.isoformat(timespec="minutes"),
            "demo": res.dry_run,
            "admin": res.admin,
            "modules": res.modules,
            "counts": {s.value: n for s, n in c.items()},
            "max_score": max((f.score for f in res.findings), default=0),
            "warnings": res.errors[:5],
        },
        "attack_techniques": [{"id": tid, "name": n, "items": k} for tid, n, k in attack_summary(res.findings)[:8]],
        "top_findings": top,
    }
    return json.dumps(data, ensure_ascii=False)


def system_prompt() -> str:
    lang = "inglés" if get_language() == "en" else "español"
    return (
        f"Eres el asistente de seguridad de win11-triage {__version__}, una herramienta defensiva de triaje para "
        "Windows 11. Ayudas a una persona, a menudo sin formación técnica, a entender los resultados de un análisis "
        "de su equipo y a decidir qué hacer.\n"
        "Reglas:\n"
        f"- Responde siempre en {lang}, de forma clara y breve (viñetas cortas; nada de relleno).\n"
        "- Básate solo en los datos del análisis. Si necesitas detalle, usa las herramientas (get_finding, "
        "list_findings, process_chain). No inventes hashes, rutas ni detecciones.\n"
        "- Cita los elementos por nombre y id. Distingue lo confirmado (VirusTotal, MalwareBazaar, Defender) de lo "
        "que solo es sospechoso.\n"
        "- Recomienda primero acciones reversibles (desconectar de la red, desactivar una entrada, analizar con "
        "Defender) antes que borrar. Nunca sugieras desactivar el antivirus ni ejecutar código descargado.\n"
        "- El puntaje va de 0 a 100: ≥ 70 o detección en VirusTotal = detectado; 30–69 = revisar.\n"
        "- <usuario> y <equipo> son marcadores de anonimización: no son errores.\n"
        "- Si la pregunta no tiene que ver con la seguridad del equipo o el análisis, dilo amablemente."
    )


@dataclass
class Agent:
    res: TriageResult
    config: AgentConfig = field(default_factory=AgentConfig.from_env)
    session: Any = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.redact = Redactor(self.res)
        self.tools = Toolbox(self.res, self.redact)
        self.session = self.session or new_session()

    def _chat(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "User-Agent": f"win11-triage/{__version__}"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        body = {"model": self.config.model, "messages": messages, "tools": TOOLS, "temperature": 0.2}
        try:
            r = self.session.post(
                self.config.base_url.rstrip("/") + "/chat/completions", json=body, headers=headers, timeout=90
            )
        except requests.RequestException as e:
            raise AgentError(f"No se pudo conectar con {self.config.provider}: {e}") from e
        if r.status_code in (401, 403):
            raise AgentError("La clave del asistente no es válida (revisa GROQ_API_KEY en Ajustes).")
        if r.status_code == 429:
            raise AgentError("Límite gratuito alcanzado por ahora: espera un minuto y vuelve a preguntar.")
        if r.status_code >= 400:
            raise AgentError(f"{self.config.provider} respondió {r.status_code}: {r.text[:200]}")
        try:
            return r.json()["choices"][0]["message"]
        except (ValueError, KeyError, IndexError) as e:
            raise AgentError(f"Respuesta inesperada del modelo: {e}") from e

    def ask(self, question: str, on_tool: Callable[[str], None] = lambda _n: None) -> str:
        if not self.config.ready:
            raise AgentError("Falta la clave de Groq: configúrala en Ajustes → Asistente de IA (es gratuita).")
        context = self.redact(summary_context(self.res))
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt()},
            {"role": "system", "content": f"Datos del análisis (JSON):\n{context}"},
            *self.history[-MAX_HISTORY:],
            {"role": "user", "content": self.redact(question)},
        ]
        for _ in range(MAX_STEPS):
            msg = self._chat(messages)
            calls = msg.get("tool_calls") or []
            if not calls:
                answer = (msg.get("content") or "").strip() or "(sin respuesta)"
                self.history += [
                    {"role": "user", "content": self.redact(question)},
                    {"role": "assistant", "content": answer},
                ]
                return answer
            messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
            for call in calls:
                fn = call.get("function", {})
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = {}
                on_tool(name)
                messages.append(
                    {"role": "tool", "tool_call_id": call.get("id", ""), "content": self.tools.call(name, args)}
                )
        raise AgentError("El asistente no llegó a una respuesta (demasiados pasos). Reformula la pregunta.")

    def reset(self) -> None:
        self.history.clear()


SUGGESTIONS = (
    "¿Qué debería revisar primero?",
    "¿Mi equipo está infectado?",
    "Explícame el hallazgo más grave en palabras sencillas",
    "¿Qué técnicas de ataque se ven y qué significan?",
)
