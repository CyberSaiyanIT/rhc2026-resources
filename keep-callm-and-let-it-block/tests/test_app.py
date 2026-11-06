import json
import types

import httpx
import pytest
from conftest import ATTACKER, NAT, import_app
from fastapi.testclient import TestClient

from romhack import splunk

app_module = import_app()

SAME_ORIGIN = {"origin": "http://testserver"}


@pytest.fixture
def searches():
    return []


@pytest.fixture
def api(workshop, monkeypatch, searches):
    monkeypatch.setattr(app_module, "portal_page", types.SimpleNamespace(render=lambda config: "<html>portal stub</html>"))

    def search(spl, run_id):
        searches.append((spl, run_id))
        if "many" in spl:
            return [{"n": index} for index in range(120)]
        if "too-big" in spl:
            raise ValueError("Unexpected value")
        if "broken" in spl:
            raise RuntimeError("Unknown search command")
        if "offline" in spl:
            raise httpx.ConnectError("refused")
        return [{"src_ip": ATTACKER}]

    return TestClient(app_module.create_app(workshop, search=search), raise_server_exceptions=False)


@pytest.fixture
def run(api):
    return api.post("/api/start", json={"phase": "B"}).json()["run_id"]


def test_health_and_portal(api):
    assert api.get("/health").json() == {"status": "ok"}
    page = api.get("/")
    assert page.status_code == 200 and "portal stub" in page.text and page.headers["content-type"].startswith("text/html")


def test_state_shape(api, run):
    api.post("/api/alerts", json={"run_id": run, "src_ip": ATTACKER, "scenario": "scanning", "count": "16"})
    response = api.get("/api/state")
    body = response.json()
    assert response.headers["cache-control"] == "no-store"
    assert set(body) == {"phase", "run_id", "running", "phases", "production", "checklist", "completed", "alerts", "operations", "approvals", "links"}
    assert (body["phase"], body["run_id"], body["running"]) == ("B", run, True)
    assert body["phases"] == ["Base", "A", "B", "C1", "C2", "C3"]
    assert body["production"]["color"] == "gray" and body["production"]["evidence_errors"] == []
    assert [step["step"] for step in body["checklist"]] == ["alert_delivered", "attacker_blocked", "green_held"]
    assert body["completed"] == [] and body["operations"] == [] and body["approvals"] == []
    [alert] = body["alerts"]
    assert alert["src_ip"] == ATTACKER and alert["status"] == "pending" and alert["attempts"] == 0
    assert {"event_id", "last_error", "evidence_status", "created_at"} <= set(alert)


def test_state_operations_newest_first_and_bounded(api, run):
    for index in range(12):
        api.post("/api/remediations", json={"action": "block", "src_ip": ATTACKER, "run_id": run, "idempotency_key": f"k{index}"})
    operations = api.get("/api/state").json()["operations"]
    assert len(operations) == 10
    assert [op["created_at"] for op in operations] == sorted((op["created_at"] for op in operations), reverse=True)


def test_start_replay_stop(api):
    started = api.post("/api/start", json={"phase": "C1"})
    assert started.status_code == 200 and started.json()["phase"] == "C1"
    replayed = api.post("/api/replay").json()
    assert replayed["phase"] == "C1" and replayed["run_id"] != started.json()["run_id"]
    stopped = api.post("/api/stop").json()
    assert stopped["running"] is False
    assert api.get("/api/state").json()["production"]["label"] == "Scenario stopped"


@pytest.mark.parametrize("body", [{"phase": "Z"}, {}, {"phase": None}])
def test_start_invalid_phase(api, body):
    assert api.post("/api/start", json=body).status_code == 422


def test_workflow_download(api, config, tmp_path):
    directory = tmp_path / "workflows"
    directory.mkdir()
    (directory / "B.json").write_text(json.dumps({"name": "B"}))
    response = api.get("/workflows/B.json")
    assert response.status_code == 200 and response.json() == {"name": "B"}
    assert response.headers["content-type"] == "application/json"
    assert 'filename="romhack-B.json"' in response.headers["content-disposition"]
    assert api.get("/workflows/A.json").status_code == 404
    assert api.get("/workflows/Z.json").status_code == 404
    assert api.get("/workflows/..%2Fsecret.json").status_code == 404


def test_asset_served(api):
    response = api.get("/assets/goku.png")
    assert response.status_code == 200 and response.headers["content-type"] == "image/png"


def test_missing_asset_404(api):
    assert api.get("/assets/missing.png").status_code == 404
    assert api.get("/assets/..%2Fapp.py").status_code == 404


def test_alert_route(api, run):
    response = api.post("/api/alerts", json={"result": {"run_id": run, "src_ip": ATTACKER, "count": 16}})
    assert response.status_code == 202 and response.json()["payload"]["count"] == "16"
    assert api.post("/api/alerts", json={"run_id": "old", "src_ip": ATTACKER}).status_code == 409


def test_remediation_routes(api, run):
    response = api.post("/api/remediations", json={"action": "block", "src_ip": ATTACKER, "run_id": run, "idempotency_key": "k1"})
    assert response.status_code == 202
    operation = response.json()
    assert operation["status"] == "queued" and operation["is_current_run"] is True
    fetched = api.get(f"/api/operations/{operation['id']}")
    assert fetched.status_code == 200 and fetched.json()["id"] == operation["id"]
    assert api.get("/api/operations/unknown").status_code == 404


@pytest.mark.parametrize("change,status", [
    ({"src_ip": "999.1.1.1"}, 422),
    ({"src_ip": "203.0.113.9"}, 409),
    ({"run_id": "stale"}, 409),
    ({"action": "drop"}, 409),
    ({"ttl_seconds": 60}, 409),
    ({"ttl_seconds": "soon"}, 422),
    ({"idempotency_key": None}, 422),
])
def test_remediation_errors(api, run, change, status):
    body = {"action": "block", "src_ip": ATTACKER, "run_id": run, "idempotency_key": "k1", **change}
    response = api.post("/api/remediations", json=body)
    assert response.status_code == status and response.json()["detail"]


def test_remediation_idempotency_conflict(api, run):
    body = {"action": "block", "src_ip": ATTACKER, "run_id": run, "idempotency_key": "k1"}
    assert api.post("/api/remediations", json=body).status_code == 202
    assert api.post("/api/remediations", json=body).status_code == 202
    assert api.post("/api/remediations", json={**body, "src_ip": NAT}).status_code == 409


def test_audit_route_clips_long_text(api, run, events):
    evidence = ["e" * 1500] + [{"k": i} for i in range(30)]
    response = api.post("/api/audit", json={"run_id": run, "event_id": "evt:Agent", "kind": "verdict", "decision": "allow",
                                            "reasoning": "r" * 5000, "evidence": evidence})
    assert response.status_code == 202
    body = response.json()
    assert len(body["reasoning"]) == 4000 and body["reasoning"].endswith("…[truncated]")
    assert len(body["evidence"]) == 20
    assert len(body["evidence"][0]) == 1000 and body["evidence"][0].endswith("…[truncated]")
    assert body["evidence"][1] == '{"k": 0}'
    assert [e["reasoning"] for e in events if e["source"] == "audit"] == [body["reasoning"]]


def test_audit_short_text_untouched(api, run):
    body = api.post("/api/audit", json={"run_id": run, "event_id": "e", "kind": "verdict", "decision": True,
                                        "reasoning": "fine", "evidence": ["one"]}).json()
    assert body["reasoning"] == "fine" and body["evidence"] == ["one"] and body["decision"] is True


@pytest.mark.parametrize("change,status", [
    ({"decision": "x" * 101}, 422),
    ({"kind": "k" * 41}, 422),
    ({"run_id": ""}, 422),
    ({"run_id": "stale"}, 409),
])
def test_audit_errors(api, run, change, status):
    body = {"run_id": run, "event_id": "e", "kind": "verdict", "decision": "block", **change}
    assert api.post("/api/audit", json=body).status_code == status


def test_minimal_audit_needs_only_run_and_decision(api, run):
    body = api.post("/api/audit", json={"run_id": run, "src_ip": NAT, "decision": "allow"}).json()
    assert body["kind"] == "workflow" and body["event_id"]


def test_validation_errors_name_the_missing_fields(api):
    response = api.post("/api/audit", json={"decision": "allow"})
    assert response.status_code == 422 and response.json()["detail"] == "run_id: field required"


def test_intelligence(api):
    reputation = api.get("/api/intelligence/reputation", params={"ip": NAT}).json()
    assert reputation["simulated"] is True and reputation["score"] == 45 and "network" not in reputation
    context = api.get("/api/intelligence/context", params={"ip": NAT}).json()
    assert context["shared_nat"] is True and "score" not in context
    assert api.get("/api/intelligence/reputation", params={"ip": "192.0.2.1"}).json()["status"] == "unknown"
    assert api.get("/api/intelligence/reputation", params={"ip": "198.51.100.99"}).status_code == 503
    assert api.get("/api/intelligence/reputation", params={"ip": "nope"}).status_code == 422
    assert api.get("/api/intelligence/whois", params={"ip": NAT}).status_code == 404


def test_search_passes_the_current_run(api, run, searches):
    response = api.post("/api/search", json={"search": "index=romhack", "run_id": run})
    assert response.status_code == 200 and response.json() == {"results": [{"src_ip": ATTACKER}], "truncated": False}
    assert searches == [("index=romhack", run)]


def test_large_search_results_are_trimmed_not_refused(api, run):
    body = api.post("/api/search", json={"search": "many", "run_id": run}).json()
    assert len(body["results"]) == app_module.SEARCH_ROWS and body["truncated"] is True and "stats" in body["note"]


def test_fit_halves_rows_until_they_fit():
    rows, truncated = app_module.fit([{"blob": "x" * 5000} for _ in range(20)])
    assert truncated and len(rows) * 5000 <= app_module.SEARCH_BYTES


def test_splunk_query_errors_reach_the_agent(workshop, config):
    transport = httpx.MockTransport(lambda request: httpx.Response(400, json={"messages": [{"type": "FATAL", "text": "Unknown search command 'foo'."}]}))
    client = TestClient(app_module.create_app(workshop, search=lambda spl, run_id: splunk.search(config, spl, run_id=run_id, http=httpx.Client(transport=transport))))
    run = client.post("/api/start", json={"phase": "B"}).json()["run_id"]
    response = client.post("/api/search", json={"search": "| foo", "run_id": run})
    assert response.status_code == 400 and "Unknown search command 'foo'" in response.json()["detail"]


@pytest.mark.parametrize("spl,status", [("too-big", 502), ("broken", 502), ("offline", 502)])
def test_search_error_mapping(api, run, spl, status):
    assert api.post("/api/search", json={"search": spl, "run_id": run}).status_code == status


def test_search_validation(api, run, searches):
    assert api.post("/api/search", json={"search": "x", "run_id": "stale"}).status_code == 409
    assert api.post("/api/search", json={"search": "", "run_id": run}).status_code == 422
    assert api.post("/api/search", json={"search": "x" * 8001, "run_id": run}).status_code == 422
    assert searches == []


def test_malformed_splunk_output_is_a_search_failure(workshop, config):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html>proxy error</html>"))
    client = TestClient(app_module.create_app(workshop, search=lambda spl, run_id: splunk.search(config, spl, run_id=run_id, http=httpx.Client(transport=transport))))
    run = client.post("/api/start", json={"phase": "B"}).json()["run_id"]
    assert client.post("/api/search", json={"search": "index=romhack", "run_id": run}).status_code == 502


def test_approval_routes(api, run):
    created = api.post("/api/approvals", json={"url": "http://localhost:5678/form-waiting/42", "run_id": run, "src_ip": ATTACKER})
    assert created.status_code == 201
    approval_id = created.json()["id"]
    assert api.get(f"/api/approvals/{approval_id}").json()["status"] == "pending"
    assert [a["id"] for a in api.get("/api/state").json()["approvals"]] == [approval_id]
    assert api.post(f"/api/approvals/{approval_id}/validate").json()["status"] == "approved"
    assert api.post(f"/api/approvals/{approval_id}/validate").status_code == 409
    assert api.post(f"/api/approvals/{approval_id}/deny").status_code == 409

    other = api.post("/api/approvals", json={"url": "http://localhost:5678/webhook-waiting/7", "run_id": run, "src_ip": NAT}).json()
    assert api.post(f"/api/approvals/{other['id']}/deny").json()["status"] == "denied"


def test_approval_route_errors(api, run):
    assert api.post("/api/approvals", json={"url": "http://evil.example/form-waiting/1", "run_id": run, "src_ip": NAT}).status_code == 409
    assert api.post("/api/approvals", json={"url": "http://localhost:5678/form-waiting/" + "a" * 2048, "run_id": run, "src_ip": NAT}).status_code == 422
    assert api.post("/api/approvals", json={"url": "http://localhost:5678/form-waiting/1", "run_id": "stale", "src_ip": NAT}).status_code == 409
    # Unknown approvals are reported as Rejected (409), like every workshop refusal.
    assert api.get("/api/approvals/missing").status_code == 404
    assert api.post("/api/approvals/missing/validate").status_code == 404


def test_cross_site_post_refused(api, run):
    response = api.post("/api/start", json={"phase": "A"}, headers={"origin": "http://evil.example"})
    assert response.status_code == 403 and response.json()["detail"] == "Cross-site request refused"
    assert api.post("/api/stop", headers={"origin": "null"}).status_code == 403
    assert api.post("/api/remediations", headers={"origin": "http://testserver.evil.example"},
                    json={"action": "block", "src_ip": ATTACKER, "run_id": run, "idempotency_key": "k"}).status_code == 403
    state = api.get("/api/state").json()
    assert (state["phase"], state["run_id"], state["running"], state["operations"]) == ("B", run, True, [])


def test_same_origin_and_originless_posts_allowed(api):
    assert api.post("/api/start", json={"phase": "A"}, headers=SAME_ORIGIN).status_code == 200
    assert api.post("/api/start", json={"phase": "A"}, headers={"origin": "http://localhost:8080", "host": "localhost:8080"}).status_code == 200
    assert api.post("/api/stop").status_code == 200
    assert api.get("/api/state", headers={"origin": "http://evil.example"}).status_code == 200
