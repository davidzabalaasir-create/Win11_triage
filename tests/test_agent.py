"""Asistente de IA: bucle de herramientas, anonimización y errores, con un servidor simulado."""

import json

import pytest

from win11_triage import agent, cli
from win11_triage.engine import TriageEngine, TriageOptions


class Resp:
    def __init__(self, code, body):
        self.status_code, self._b, self.text = code, body, json.dumps(body)

    def json(self):
        return self._b


class FakeLLM:
    """Primero pide get_finding(0); después responde citando lo recibido."""

    def __init__(self, code=200):
        self.code, self.requests = code, []

    def post(self, url, json=None, headers=None, timeout=None):
        self.requests.append({"url": url, "body": json, "headers": headers})
        if self.code != 200:
            return Resp(self.code, {"error": "x"})
        msgs = json["messages"]
        if msgs[-1]["role"] != "tool":
            call = {"id": "c1", "type": "function", "function": {"name": "get_finding", "arguments": '{"id": 0}'}}
            return Resp(200, {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [call]}}]})
        data = __import__("json").loads(msgs[-1]["content"])
        answer = f"Lo más grave es **{data['name']}** (score {data['score']}). Paso 1: {data['recommended_steps'][0]}"
        return Resp(200, {"choices": [{"message": {"role": "assistant", "content": answer}}]})


@pytest.fixture
def result(tmp_path):
    return TriageEngine(TriageOptions(dry_run=True, autoruns=True, processes=True, config_dir=tmp_path), {}).run()


def _cfg():
    return agent.AgentConfig(provider="groq", base_url="https://api.groq.com/openai/v1", model="m", api_key="k")


def test_tool_loop_and_history(result):
    llm = FakeLLM()
    tools_used = []
    a = agent.Agent(result, config=_cfg(), session=llm)
    answer = a.ask("¿Qué reviso primero?", on_tool=tools_used.append)
    assert "score 100" in answer and tools_used == ["get_finding"]
    first = llm.requests[0]
    assert first["url"].endswith("/chat/completions") and first["headers"]["Authorization"] == "Bearer k"
    assert {t["function"]["name"] for t in first["body"]["tools"]} >= {"list_findings", "get_finding"}
    assert len(a.history) == 2
    a.ask("¿Y después?")
    assert len(llm.requests) == 4 and llm.requests[2]["body"]["messages"][2]["role"] == "user"


def test_redaction_hides_user_and_host(result):
    result.host, result.user = "PC-DE-ANA", "usuario"
    llm = FakeLLM()
    agent.Agent(result, config=_cfg(), session=llm).ask("hola PC-DE-ANA")
    sent = json.dumps([r["body"]["messages"] for r in llm.requests])
    assert "usuario" not in sent.replace("<usuario>", "") and "PC-DE-ANA" not in sent
    assert "<usuario>" in sent and "<equipo>" in sent


def test_tools_read_only_and_filters(result):
    tb = agent.Toolbox(result, agent.Redactor(result))
    listed = json.loads(tb.call("list_findings", {"status": "DETECTADO", "limit": 3}))
    assert listed["total"] >= 3 and len(listed["findings"]) == 3
    assert "error" in json.loads(tb.call("get_finding", {"id": 999}))
    assert "error" in json.loads(tb.call("rm_rf", {}))
    sug = json.loads(tb.call("suggest_allowlist", {"id": 0}))
    assert sug["warning"] and ("hashes" in sug["whitelist_json_entry"] or "paths" in sug["whitelist_json_entry"])
    chains = json.loads(tb.call("process_chain", {}))
    assert chains["chains"]


@pytest.mark.parametrize("code, text", [(401, "clave"), (429, "Límite"), (500, "500")])
def test_http_errors(result, code, text):
    with pytest.raises(agent.AgentError, match=text):
        agent.Agent(result, config=_cfg(), session=FakeLLM(code)).ask("x")


def test_missing_key_and_config(result, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    cfg = agent.AgentConfig.from_env()
    assert cfg.provider == "groq" and cfg.model == "openai/gpt-oss-120b" and not cfg.ready
    with pytest.raises(agent.AgentError, match="Groq"):
        agent.Agent(result, config=cfg, session=FakeLLM()).ask("x")
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    assert agent.AgentConfig.from_env().ready  # local: sin clave


def test_cli_report_and_ask(tmp_path, monkeypatch, capsys):
    assert cli.main(["--dry-run", "--config-dir", str(tmp_path), "--format", "json"]) == 0
    rep = next((tmp_path / "reportes").glob("*.json"))
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.setattr(agent, "new_session", lambda: FakeLLM())
    assert cli.main(["--report", str(rep), "--config-dir", str(tmp_path), "--ask", "¿qué hago?", "--no-color"]) == 0
    assert "Lo más grave" in capsys.readouterr().out
