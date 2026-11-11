import httpx
import pytest
from conftest import ATTACKER, BENIGN, NAT, VPN, block

from romhack import progress, workers
from romhack.runtime import alert_key
from romhack.target import SIGNATURE


def visit(site, ip, run_id, method="GET", path="/", **headers):
    return site.request(method, path, headers={"X-Romhack-Client-IP": ip, "X-Romhack-Run-ID": run_id, **headers})


# --- simulated website + WAF -------------------------------------------------

def test_allowed_request_logs_waf_allow_and_web(workshop, site, events):
    run = workshop.start("B")["run_id"]
    response = visit(site, BENIGN, run)
    assert response.status_code == 200 and response.text == "Hello RomHack!\n"
    waf, web = events
    assert waf["source"] == "waf" and waf["action"] == "ALLOW" and waf["terminating_rule"] == "default-allow"
    assert waf["managed_match"] is False and waf["matched_rules"] == []
    assert web["source"] == "web" and web["status"] == 200 and web["src_ip"] == BENIGN and web["run_id"] == run
    assert web["auth_outcome"] == "none" and web["application_event"] == "public"


def test_blocked_ip_gets_403_and_only_a_waf_block(workshop, site, probe, events):
    workshop.start("B")
    block(workshop, probe, ATTACKER)
    events.clear()
    response = visit(site, ATTACKER, workshop.state()["run_id"], path="/login")
    assert response.status_code == 403
    [event] = events
    assert event["source"] == "waf" and event["action"] == "BLOCK" and event["terminating_rule"] == "workshop-blocklist"
    assert event["src_ip"] == ATTACKER and event["path"] == "/login"


@pytest.mark.parametrize("run_id", ["verification", ""])
def test_verification_and_unlabelled_requests_are_not_logged(workshop, site, events, run_id):
    workshop.start("B")
    assert visit(site, BENIGN, run_id).status_code == 200
    assert events == []


def test_propfind_matches_managed_rule(workshop, site, events):
    run = workshop.start("B")["run_id"]
    assert visit(site, ATTACKER, run, method="PROPFIND", path="/missing/admin-1").status_code == 404
    waf, web = events
    assert waf["managed_match"] is True and waf["matched_rules"] == [SIGNATURE] and waf["action"] == "ALLOW"
    assert waf["http_method"] == "PROPFIND" and web["status"] == 404


def test_routes_and_synthetic_identity(workshop, site, events):
    run = workshop.start("C1")["run_id"]
    login = visit(site, VPN, run, path="/login", **{"X-Romhack-User": "employee-01", "X-Romhack-Session": "s" * 200})
    assert login.status_code == 401
    web = events[-1]
    assert web["auth_outcome"] == "failure" and web["application_event"] == "authentication"
    assert web["synthetic_user"] == "employee-01" and len(web["synthetic_session"]) == 80
    assert visit(site, VPN, run, path="/app/orders").json() == {"simulated": True, "activity": "view orders"}
    assert events[-1]["application_event"] == "authenticated_use"


# --- traffic -----------------------------------------------------------------

class Recorder:
    def __init__(self):
        self.calls = []

    def request(self, method, url, headers):
        self.calls.append((method, url, headers))


def test_traffic_c1_sends_vpn_story_first(workshop):
    run = workshop.start("C1")["run_id"]
    http = Recorder()
    workers.traffic_once(workshop, http)
    assert len(http.calls) == 8
    assert {headers["X-Romhack-Client-IP"] for _, _, headers in http.calls} == {VPN}
    assert [url.removeprefix("http://127.0.0.1:8081") for _, url, _ in http.calls] == ["/login"] * 5 + ["/session/login", "/app/home", "/app/orders"]
    assert all(h["X-Romhack-Run-ID"] == run and h["X-Romhack-User"] == "employee-01" for _, _, h in http.calls)
    assert workshop.state()["traffic_offset"] == 8

    workers.traffic_once(workshop, http)
    assert len(http.calls) == 11
    assert [(m, h["X-Romhack-Client-IP"]) for m, _, h in http.calls[8:]] == [("PROPFIND", ATTACKER)] * 3


def test_traffic_without_vpn_uses_configured_batch(workshop):
    workshop.config["traffic_requests_per_pass"] = 5
    workshop.start("B")
    http = Recorder()
    workers.traffic_once(workshop, http)
    assert [(m, h["X-Romhack-Client-IP"]) for m, _, h in http.calls] == [("PROPFIND", ATTACKER)] * 5


def test_traffic_wraps_around_the_scenario(workshop):
    workshop.start("B")
    workshop.store.update("lab", lambda old: {**old, "traffic_offset": 43})
    http = Recorder()
    workers.traffic_once(workshop, http)
    assert [h["X-Romhack-Client-IP"] for _, _, h in http.calls] == [BENIGN, ATTACKER, ATTACKER]


def test_no_traffic_when_stopped(workshop):
    http = Recorder()
    workers.traffic_once(workshop, http)
    workshop.start("C1")
    workshop.stop()
    workers.traffic_once(workshop, http)
    assert http.calls == []


def test_traffic_survives_website_errors(workshop):
    workshop.start("B")

    class Down:
        def request(self, *args, **kwargs):
            raise httpx.ConnectError("down")

    workers.traffic_once(workshop, Down())
    assert workshop.state()["traffic_offset"] == 3


def test_traffic_reaches_the_simulated_website(workshop, site, events):
    workshop.start("C1")
    workers.traffic_once(workshop, site)
    workers.traffic_once(workshop, site)
    assert {e["src_ip"] for e in events} == {VPN, ATTACKER}
    assert {e["source"] for e in events} == {"waf", "web"}


# --- alert delivery ----------------------------------------------------------

class Webhook:
    def __init__(self, status=200, error=None):
        self.status, self.error, self.requests = status, error, []
        self.client = httpx.Client(transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return httpx.Response(self.status)


def raise_alert(workshop, ip=ATTACKER):
    return workshop.alert({"run_id": workshop.state()["run_id"], "src_ip": ip, "scenario": "scanning", "count": "16"})


def stored_alert(workshop, ip=ATTACKER, run_id=None):
    return workshop.store.get(alert_key(run_id or workshop.state()["run_id"], ip))


def test_dispatch_delivers_to_webhook(workshop):
    workshop.start("B")
    alert = raise_alert(workshop)
    hook = Webhook()
    workers.dispatch_once(workshop, hook.client, now=100.0)
    [request] = hook.requests
    assert str(request.url) == workshop.config["n8n_webhook_url"]
    assert request.method == "POST" and httpx.Response(200, content=request.content).json() == alert["payload"]
    saved = stored_alert(workshop)
    assert (saved["status"], saved["attempts"], saved["delivered_at"], saved["last_error"]) == ("delivered", 1, 100.0, "")
    assert "alert_delivered" in progress.get(workshop.store)["steps"]
    workers.dispatch_once(workshop, hook.client, now=200.0)
    assert len(hook.requests) == 1


def test_dispatch_404_means_workflow_not_published_and_backs_off(workshop):
    workshop.start("B")
    raise_alert(workshop)
    hook = Webhook(status=404)
    workers.dispatch_once(workshop, hook.client, now=100.0)
    saved = stored_alert(workshop)
    assert saved["status"] == "retry" and saved["attempts"] == 1
    assert saved["last_error"] == "workflow not published (n8n answered 404)"
    assert saved["next_attempt"] == 102.0

    workers.dispatch_once(workshop, hook.client, now=101.0)
    assert len(hook.requests) == 1
    workers.dispatch_once(workshop, hook.client, now=102.0)
    assert len(hook.requests) == 2
    assert stored_alert(workshop)["next_attempt"] == 106.0

    hook.status = 200
    workers.dispatch_once(workshop, hook.client, now=106.0)
    assert stored_alert(workshop)["status"] == "delivered" and stored_alert(workshop)["attempts"] == 3


def test_dispatch_backoff_is_capped(workshop):
    workshop.start("B")
    raise_alert(workshop)
    workshop.store.update(alert_key(workshop.state()["run_id"], ATTACKER), lambda old: {**old, "attempts": 9})
    workers.dispatch_once(workshop, Webhook(status=500).client, now=100.0)
    saved = stored_alert(workshop)
    assert saved["next_attempt"] == 130.0 and "500" in saved["last_error"]


def test_dispatch_connection_error_retries(workshop):
    workshop.start("B")
    raise_alert(workshop)
    workers.dispatch_once(workshop, Webhook(error=httpx.ConnectError("refused")).client, now=100.0)
    saved = stored_alert(workshop)
    assert saved["status"] == "retry" and saved["last_error"] == "refused"


def test_dispatch_marks_old_run_alerts_stale(workshop):
    old = workshop.start("B")["run_id"]
    raise_alert(workshop)
    workshop.start("B")
    hook = Webhook()
    workers.dispatch_once(workshop, hook.client, now=100.0)
    assert hook.requests == []
    assert stored_alert(workshop, run_id=old)["status"] == "stale"


def test_dispatch_holds_vpn_alert_until_evidence_ready(workshop):
    workshop.start("C1")
    raise_alert(workshop, VPN)
    hook = Webhook()
    workers.dispatch_once(workshop, hook.client, now=100.0)
    assert hook.requests == [] and stored_alert(workshop, VPN)["status"] == "pending"

    workers.evidence_once(workshop, check=lambda run_id, ip: True, clock=lambda: stored_alert(workshop, VPN)["created_at"] + 1)
    assert stored_alert(workshop, VPN)["evidence_status"] == "ready"
    workers.dispatch_once(workshop, hook.client, now=100.0)
    assert len(hook.requests) == 1 and stored_alert(workshop, VPN)["status"] == "delivered"


# --- evidence readiness ------------------------------------------------------

def test_evidence_not_ready_backs_off(workshop):
    run = workshop.start("C1")["run_id"]
    created = raise_alert(workshop, VPN)["created_at"]
    checks = []

    def check(run_id, ip):
        checks.append((run_id, ip))
        return False

    workers.evidence_once(workshop, check=check, clock=lambda: created + 1)
    saved = stored_alert(workshop, VPN)
    assert checks == [(run, VPN)]
    assert saved["evidence_status"] == "waiting" and saved["evidence_attempts"] == 1
    assert saved["evidence_next_attempt"] == created + 3

    workers.evidence_once(workshop, check=check, clock=lambda: created + 2)
    assert len(checks) == 1


def test_evidence_check_errors_count_as_not_ready(workshop):
    workshop.start("C1")
    created = raise_alert(workshop, VPN)["created_at"]

    def broken(run_id, ip):
        raise RuntimeError("splunk down")

    workers.evidence_once(workshop, check=broken, clock=lambda: created)
    assert stored_alert(workshop, VPN)["evidence_status"] == "waiting"


def test_evidence_timeout_fails_alert(workshop):
    from romhack.production import status

    workshop.start("C1")
    created = raise_alert(workshop, VPN)["created_at"]
    workers.evidence_once(workshop, check=lambda run_id, ip: True, clock=lambda: created + 180)
    saved = stored_alert(workshop, VPN)
    assert saved["evidence_status"] == "failed" and "Splunk did not index" in saved["evidence_error"]
    assert status(workshop)["evidence_errors"] == [saved["evidence_error"]]
    hook = Webhook()
    workers.dispatch_once(workshop, hook.client, now=created + 200)
    assert hook.requests == []


def test_evidence_for_old_run_is_stale(workshop):
    old = workshop.start("C1")["run_id"]
    raise_alert(workshop, VPN)
    workshop.start("C1")
    workers.evidence_once(workshop, check=lambda run_id, ip: pytest.fail("must not check stale runs"))
    saved = stored_alert(workshop, VPN, run_id=old)
    assert saved["status"] == "stale" and saved["evidence_status"] == "stale"


def test_probe_reports_status_or_none():
    seen = []

    def handle(request):
        seen.append(request)
        if request.headers["X-Romhack-Client-IP"] == NAT:
            raise httpx.ConnectError("down")
        return httpx.Response(403)

    probe = workers.Probe({"target_url": "http://site:8081"}, http=httpx.Client(transport=httpx.MockTransport(handle)))
    assert probe(ATTACKER) == 403
    assert probe(NAT) is None
    assert str(seen[0].url) == "http://site:8081/" and seen[0].headers["X-Romhack-Run-ID"] == "verification"
