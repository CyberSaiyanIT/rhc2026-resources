"""Opt-in smoke test against a disposable, real n8n 2.40.5 (stable) container.

Never point it at the lab's own n8n: it creates an owner account, a test-only
model credential and workflows. For example:

    docker run -d --rm --name romhack-n8n-test -p 127.0.0.1:15678:5678 \\
        -e N8N_SECURE_COOKIE=false -e WEBHOOK_URL=http://localhost:15678/ docker.n8n.io/n8nio/n8n:stable
    ROMHACK_N8N_URL=http://localhost:15678 uv run --extra test pytest -q tests/test_n8n_integration.py

The workflows call a local mock of the workshop API instead of http://workshop:8000.
For C1-C3 the test wires an OpenAI-compatible chat model (served by the same mock)
into the agent, standing in for the model the participant connects.
Deterministic model replies validate n8n routing and tool plumbing, not AI judgment.
"""
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import httpx
import pytest
from pydantic import ValidationError

from romhack import workflows

pytestmark = pytest.mark.skipif(not os.environ.get("ROMHACK_N8N_URL"), reason="Opt-in real n8n container smoke")

TEST_MODEL = "test-model"
AGENT = "King Kai - AI Agent"
PROMPT = "Investigate this Splunk alert"


def with_test_model(workflow, credential):
    """TEST ONLY: the shipped C1-C3 leave the agent's Chat Model input for the participant."""
    agent = next(node for node in workflow["nodes"] if node["name"] == AGENT)
    workflow["nodes"].append({
        "id": "testmodel0000001", "name": "Test chat model", "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "typeVersion": 1.3,
        "position": [agent["position"][0], 450], "credentials": {"openAiApi": {"id": credential["id"], "name": credential["name"]}},
        "parameters": {"model": {"__rl": True, "value": TEST_MODEL, "mode": "id"}, "options": {"maxTokens": 2000, "temperature": 0, "maxRetries": 0}, "responsesApiEnabled": False},
    })
    workflow["connections"]["Test chat model"] = {"ai_languageModel": [[{"node": AGENT, "type": "ai_languageModel", "index": 0}]]}
    return workflow


def test_real_n8n_imports_and_runs_checkpoints(monkeypatch):
    from romhack.app import Action, Approval, Audit

    base = os.environ["ROMHACK_N8N_URL"]
    mock_host = os.environ.get("ROMHACK_N8N_MOCK_HOST", "host.docker.internal")
    requests = []
    search_records = [
        {"run_id": "test-run", "src_ip": "198.51.100.10", "auth_outcome": "none", "application_event": "public", "uri": "/missing", "count": "16"},
        {"run_id": "test-run", "src_ip": "198.51.100.40", "auth_outcome": "success", "application_event": "authentication", "uri": "/session/login", "synthetic_user": "employee-01", "synthetic_session": "vpn-session-01"},
        {"run_id": "test-run", "src_ip": "198.51.100.40", "auth_outcome": "none", "application_event": "authenticated_use", "uri": "/app/home", "synthetic_user": "employee-01", "synthetic_session": "vpn-session-01"},
        # Contradictory old evidence must never reach the current-run tool result.
        {"run_id": "previous-run", "src_ip": "198.51.100.10", "auth_outcome": "success", "application_event": "authenticated_use"},
        {"run_id": "previous-run", "src_ip": "198.51.100.40", "auth_outcome": "failure", "application_event": "scanning"},
    ]

    class Workshop(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append((self.path, None))
            if "/intelligence/reputation" in self.path:
                result = {"score": 45 if "198.51.100.20" in self.path else 95, "simulated": True}
            elif "/intelligence/context" in self.path:
                result = {"scanner": "198.51.100.10" in self.path, "shared_nat": "198.51.100.40" in self.path, "simulated": True}
            elif "/models" in self.path:
                result = {"object": "list", "data": [{"id": TEST_MODEL, "object": "model"}]}
            else:
                result = {"status": "ok"}
            self.reply(result)

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            requests.append((self.path, payload))
            try:
                schema = {"/api/remediations": Action, "/api/approvals": Approval, "/api/audit": Audit}.get(self.path)
                if schema:
                    schema.model_validate(payload)
            except ValidationError as exc:
                return self.reply({"detail": str(exc)}, status=422)
            if self.path.endswith("/chat/completions"):
                result = self.chat(payload)
            elif self.path == "/api/approvals":
                result = {"id": "approval-test", **payload}
            elif self.path == "/api/search":
                # Deliberately do not inject body.run_id into the search: the issued
                # SPL must establish its own scope before any aggregation.
                initial = payload["search"].split("|", 1)[0]
                assert "index=romhack" in initial
                filters = dict(re.findall(r'(run_id|src_ip)="([^"]+)"', initial))
                assert filters.get("run_id") == payload["run_id"] == "test-run"
                assert filters.get("src_ip") in ("198.51.100.10", "198.51.100.40")
                result = {"results": [row for row in search_records if all(row[key] == value for key, value in filters.items())]}
                assert result["results"] and all(row["run_id"] == "test-run" for row in result["results"])
            else:
                result = {"id": "operation-test", "status": "queued", **payload}
            self.reply(result)

        def chat(self, payload):
            prompt = next(message["content"] for message in payload["messages"]
                          if isinstance(message.get("content"), str) and message["content"].startswith(PROMPT))
            alert = dict(re.findall(r"^(\w+): (.*)$", prompt, re.MULTILINE))
            vpn = alert["src_ip"] == "198.51.100.40"
            verdict = {"block": not vpn, "confidence": 0.95, "evidence": ["current-run tool records"],
                       "reasoning": "Deterministic routing fixture: recovered authentication and subsequent use" if vpn else "Deterministic routing fixture: scanner without authenticated use"}
            tools = payload.get("tools", [])
            ordinary = [tool for tool in tools if "format" not in tool["function"]["name"].lower()]
            formatter = next((tool for tool in tools if "format" in tool["function"]["name"].lower()), None)
            has_evidence = any(message.get("role") == "tool" for message in payload["messages"])
            if ordinary and not has_evidence:
                calls = []
                for index, tool in enumerate(ordinary):
                    props = tool["function"].get("parameters", {}).get("properties", {})
                    arguments = {name: f'search index=romhack run_id="{alert["run_id"]}" src_ip="{alert["src_ip"]}" | dedup event_id | sort 0 _time | table _time src_ip path uri auth_outcome application_event synthetic_user synthetic_session' for name in props}
                    calls.append({"id": f"call_{index}", "type": "function", "function": {"name": tool["function"]["name"], "arguments": json.dumps(arguments)}})
                message, reason = {"role": "assistant", "content": None, "tool_calls": calls}, "tool_calls"
            elif formatter:
                properties = formatter["function"].get("parameters", {}).get("properties", {})
                arguments = {"output": verdict} if "output" in properties else verdict
                message = {"role": "assistant", "content": None, "tool_calls": [{"id": "format_1", "type": "function", "function": {"name": formatter["function"]["name"], "arguments": json.dumps(arguments)}}]}
                reason = "tool_calls"
            else:
                message, reason = {"role": "assistant", "content": json.dumps(verdict)}, "stop"
            return {"id": "chat-test", "object": "chat.completion", "created": 0, "model": TEST_MODEL, "choices": [{"index": 0, "message": message, "finish_reason": reason}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140}}

        def reply(self, body, status=200):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("0.0.0.0", 0), Workshop)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    mock = f"http://{mock_host}:{server.server_port}"
    monkeypatch.setattr(workflows, "BASE", mock)

    def checked(response):
        assert response.is_success, f"{response.request.method} {response.request.url.path}: {response.status_code} {response.text[:3000]}"
        return response.json().get("data", response.json())

    def execution(client, workflow_id, expected="success", exclude_id=None):
        last = None
        for _ in range(60):
            results = checked(client.get("/rest/executions", params={"filter": json.dumps({"workflowId": workflow_id})})).get("results", [])
            if results:
                last = results[0]
                if last["id"] == exclude_id:
                    time.sleep(0.2)
                    continue
                if last["status"] == expected:
                    return last
                if last["status"] == "error":
                    detail = client.get("/rest/executions/" + last["id"], params={"includeData": "true"}).json()
                    pytest.fail("Workflow failed: " + json.dumps(detail)[:10000])
            time.sleep(0.5)
        pytest.fail(f"Workflow did not reach {expected}: {last}")

    def alert(client, **event):
        for _ in range(10):
            triggered = client.post("/webhook/romhack", json=event)
            if triggered.status_code != 404:
                break
            time.sleep(0.2)
        return checked(triggered)

    def answer_form(client, decision):
        approval = next(payload for path, payload in reversed(requests) if path == "/api/approvals")
        form = urlparse(approval["url"])
        form_path = form.path + ("?" + form.query if form.query else "")
        assert client.get(form_path).is_success
        response = client.post(form_path, files={"field-0": (None, decision)})
        assert response.is_success, response.text[:3000]

    def blocked(event_id):
        return any(path == "/api/remediations" and payload.get("idempotency_key") == event_id for path, payload in requests)

    try:
        with httpx.Client(base_url=base, timeout=45) as client:
            settings = checked(client.get("/rest/settings"))
            owner = {"email": "owner@romhack-test.invalid", "password": "Integration123!", "firstName": "Test", "lastName": "Owner"}
            if settings["userManagement"].get("showSetupOnFirstLoad", False):
                checked(client.post("/rest/owner/setup", json=owner))
            else:
                checked(client.post("/rest/login", json={"emailOrLdapLoginId": owner["email"], "password": owner["password"]}))
            existing = checked(client.get("/rest/workflows"))
            for item in existing if isinstance(existing, list) else existing.get("results", []):
                if item.get("active"):
                    checked(client.post(f"/rest/workflows/{item['id']}/deactivate"))
            credential = checked(client.post("/rest/credentials", json={"name": "Test model (integration only)", "type": "openAiApi",
                                                                        "data": {"apiKey": "test-only", "url": mock + "/v1"}}))
            previous = None
            for phase in workflows.PHASES:
                if previous:
                    checked(client.post(f"/rest/workflows/{previous}/deactivate"))
                body = workflows.workflow(phase)
                body.pop("id")
                if phase.startswith("C"):
                    with_test_model(body, credential)
                created = checked(client.post("/rest/workflows", json=body))
                workflow_id = previous = created["id"]
                checked(client.post(f"/rest/workflows/{workflow_id}/activate", json={"versionId": created["versionId"]}))
                event = {"run_id": "test-run", "event_id": f"test-{phase}", "src_ip": "198.51.100.10", "scenario": "scanning", "count": "16"}
                alert(client, **event)
                current = execution(client, workflow_id, "waiting" if phase in ("C2", "C3") else "success")
                if phase in ("C2", "C3"):
                    answer_form(client, "Approve")
                    execution(client, workflow_id)
                if phase != "Base":
                    assert blocked(f"test-{phase}")
                if phase == "B":
                    alert(client, **{**event, "src_ip": "198.51.100.20", "event_id": "test-B-nat"})
                    current = execution(client, workflow_id, exclude_id=current["id"])
                    assert not blocked("test-B-nat")
                if phase in ("B", "C1"):
                    # B blocks the VPN user on reputation alone; the C1 agent allows it.
                    event_id = f"test-{phase}-vpn"
                    alert(client, **{**event, "src_ip": "198.51.100.40", "event_id": event_id})
                    current = execution(client, workflow_id, exclude_id=current["id"])
                    assert blocked(event_id) is (phase == "B")
                    if phase == "C1":
                        assert any(path == "/api/audit" and payload.get("src_ip") == "198.51.100.40" and payload["decision"] == "allow" and payload["evidence"] == ["current-run tool records"] for path, payload in requests)
                if phase == "C2":
                    alert(client, **{**event, "event_id": "test-C2-deny"})
                    execution(client, workflow_id, "waiting", exclude_id=current["id"])
                    answer_form(client, "Deny")
                    execution(client, workflow_id, exclude_id=current["id"])
                    assert not blocked("test-C2-deny")
                    assert any(path.endswith("/deny") for path, _ in requests)
                    assert any(path == "/api/audit" and payload["decision"] == "deny" for path, payload in requests)
                if phase == "C3":
                    assert next(payload for path, payload in requests if path == "/api/remediations" and payload.get("idempotency_key") == "test-C3")["ttl_seconds"] == 120
                    # The server expires the block; the workflow ends after the block request.
                    assert not any(path.startswith("/api/operations/") for path, _ in requests)
                print(f"Validated n8n {phase}: execution {current['id']}")
            assert any(path == "/api/search" for path, _ in requests)
            assert any("/api/intelligence/context" in path for path, _ in requests)
            assert any(path.endswith("/validate") for path, _ in requests)
    finally:
        server.shutdown()
        server.server_close()
