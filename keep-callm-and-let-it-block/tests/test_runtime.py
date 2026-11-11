import pytest
from conftest import ATTACKER, BENIGN, NAT, VPN, block

from romhack import progress
from romhack.runtime import InvalidRequest, Rejected, alert_key


def request(workshop, ip=ATTACKER, action="block", key="k1", **extra):
    return {"action": action, "src_ip": ip, "run_id": workshop.state()["run_id"], "idempotency_key": key, **extra}


def steps(workshop):
    return set(progress.get(workshop.store)["steps"])


# --- run lifecycle -----------------------------------------------------------

def test_initial_state_is_stopped_base(workshop):
    state = workshop.state()
    assert (state["phase"], state["running"], state["run_id"]) == ("Base", False, "")


def test_start_begins_a_fresh_run_and_clears_enforcement(workshop, probe):
    first = workshop.start("A")
    block(workshop, probe, ATTACKER)
    workshop.action(request(workshop, NAT, key="pending"))
    assert workshop.state()["waf"] == [ATTACKER] and workshop.state()["pending"]

    second = workshop.start("B")
    assert second["run_id"] != first["run_id"]
    assert (second["phase"], second["running"]) == ("B", True)
    assert (second["waf"], second["blocks"], second["pending"], second["history"]) == ([], {}, [], [])
    assert second["traffic_offset"] == 0
    assert probe(ATTACKER) == 200
    assert progress.get(workshop.store)["run_id"] == second["run_id"]
    assert progress.get(workshop.store)["phase"] == "B"


def test_replay_keeps_phase_with_new_run(workshop):
    first = workshop.start("C2")
    replay = workshop.start()
    assert replay["phase"] == "C2" and replay["run_id"] != first["run_id"]


def test_unknown_phase_rejected(workshop):
    with pytest.raises(Rejected):
        workshop.start("Z")


def test_stop_keeps_run_but_not_running(workshop):
    run = workshop.start("A")["run_id"]
    stopped = workshop.stop()
    assert stopped["running"] is False and stopped["run_id"] == run


def test_stale_run_rejected(workshop):
    old = workshop.start("A")["run_id"]
    workshop.start("A")
    for run_id in (old, "", None):
        with pytest.raises(Rejected, match="stale"):
            workshop.action({"action": "block", "src_ip": ATTACKER, "run_id": run_id, "idempotency_key": "k"})


# --- action validation -------------------------------------------------------

@pytest.mark.parametrize("ip", ["not-an-ip", "2001:db8::1", "198.51.100.256", ""])
def test_action_non_ipv4_is_invalid_request(workshop, ip):
    workshop.start("A")
    with pytest.raises(InvalidRequest):
        workshop.action(request(workshop, ip))


def test_action_outside_scenario_rejected_not_invalid(workshop):
    workshop.start("A")
    with pytest.raises(Rejected, match="outside") as raised:
        workshop.action(request(workshop, "203.0.113.5"))
    assert not isinstance(raised.value, InvalidRequest)


def test_action_unknown_verb_rejected(workshop):
    workshop.start("A")
    with pytest.raises(Rejected):
        workshop.action(request(workshop, action="delete"))


@pytest.mark.parametrize("key", ["", "x" * 129])
def test_action_requires_bounded_idempotency_key(workshop, key):
    workshop.start("A")
    with pytest.raises(Rejected, match="idempotency"):
        workshop.action(request(workshop, key=key))


@pytest.mark.parametrize("phase,action,ttl", [
    ("B", "block", 60), ("C2", "block", 60), ("C3", "block", 9), ("C3", "block", 601), ("C3", "unblock", 60), ("C3", "block", 0),
])
def test_ttl_only_for_c3_blocks_in_range(workshop, phase, action, ttl):
    workshop.start(phase)
    with pytest.raises(Rejected, match="TTL"):
        workshop.action(request(workshop, action=action, ttl_seconds=ttl))


@pytest.mark.parametrize("ttl", [10, 600])
def test_ttl_bounds_accepted_in_c3(workshop, ttl):
    workshop.start("C3")
    assert workshop.action(request(workshop, ttl_seconds=ttl))["ttl_seconds"] == ttl


def test_same_idempotency_key_is_idempotent(workshop):
    workshop.start("A")
    first = workshop.action(request(workshop))
    again = workshop.action(request(workshop))
    assert first["id"] == again["id"] and first["status"] == "queued"
    assert [op["id"] for op in workshop.state()["pending"]] == [first["id"]]


@pytest.mark.parametrize("change", [{"src_ip": NAT}, {"action": "unblock"}])
def test_idempotency_key_reuse_for_other_action_rejected(workshop, change):
    workshop.start("A")
    workshop.action(request(workshop))
    with pytest.raises(Rejected, match="Idempotency key already used"):
        workshop.action({**request(workshop), **change})
    assert len(workshop.state()["pending"]) == 1


def test_same_key_in_new_run_is_a_new_operation(workshop):
    workshop.start("A")
    first = workshop.action(request(workshop))
    workshop.start("A")
    second = workshop.action(request(workshop))
    assert first["id"] != second["id"]
    assert workshop.operation(first["id"])["is_current_run"] is False


def test_unknown_operation_is_none(workshop):
    assert workshop.operation("nope") is None


# --- enforcement -------------------------------------------------------------

def test_operation_observed_only_when_probe_matches(workshop, events):
    workshop.start("A")
    operation = workshop.action(request(workshop))
    answers = {ATTACKER: 200}
    workshop.process_operations(lambda ip: answers[ip])

    applied = workshop.operation(operation["id"])
    state = workshop.state()
    assert applied["status"] == "applied"
    assert state["waf"] == [ATTACKER] and state["blocks"] == {ATTACKER: operation["id"]}
    assert [op["status"] for op in state["pending"]] == ["applied"]
    assert not [e for e in events if e["source"] == "audit"]
    assert "attacker_blocked" not in steps(workshop)

    answers[ATTACKER] = None  # website unreachable: still not observed
    workshop.process_operations(lambda ip: answers[ip])
    assert workshop.operation(operation["id"])["status"] == "applied"

    answers[ATTACKER] = 403
    workshop.process_operations(lambda ip: answers[ip])
    observed = workshop.operation(operation["id"])
    state = workshop.state()
    assert observed["status"] == "observed" and observed["completed_at"]
    assert state["pending"] == [] and [op["id"] for op in state["history"]] == [operation["id"]]
    lifecycle = [e for e in events if e["source"] == "audit"]
    assert len(lifecycle) == 1
    assert lifecycle[0] | {"timestamp": 0} == {
        "source": "audit", "event_id": "lifecycle-" + operation["id"], "run_id": state["run_id"], "timestamp": 0,
        "kind": "remediation", "action": "block", "src_ip": ATTACKER, "decision": "observed", "operation_id": operation["id"]}
    assert {"block_requested", "attacker_blocked"} <= steps(workshop)
    assert "A" in progress.get(workshop.store)["done"]


def test_blocking_a_legitimate_client_is_not_attacker_blocked(workshop, probe):
    workshop.start("A")
    assert block(workshop, probe, NAT)["status"] == "observed"
    assert probe(NAT) == 403
    assert "attacker_blocked" not in steps(workshop)


def test_unblock_restores_access(workshop, probe):
    workshop.start("A")
    block(workshop, probe, BENIGN)
    workshop.action(request(workshop, BENIGN, action="unblock", key="undo"))
    workshop.process_operations(probe)
    state = workshop.state()
    assert state["waf"] == [] and state["blocks"] == {}
    assert probe(BENIGN) == 200
    assert [op["action"] for op in state["history"]] == ["block", "unblock"]


def test_queue_is_bounded(workshop):
    workshop.start("A")
    for index in range(64):
        workshop.action(request(workshop, key=f"k{index}"))
    with pytest.raises(Rejected, match="queue is full"):
        workshop.action(request(workshop, key="one-too-many"))


def test_c3_ttl_block_expires_into_an_observed_unblock(workshop, probe, clock):
    workshop.start("C3")
    operation = block(workshop, probe, ATTACKER, ttl_seconds=30)
    assert operation["status"] == "observed"
    assert operation["expiry"]["status"] == "pending"
    assert operation["expiry"]["expires_at"] == pytest.approx(clock.now + 30)
    assert operation["expiry"]["unblock_operation"] is None
    assert "ttl_block_observed" in steps(workshop)

    clock.advance(29)
    workshop.process_operations(probe)
    assert workshop.state()["waf"] == [ATTACKER]

    clock.advance(1)
    workshop.process_operations(probe)  # expiry queues the unblock
    assert workshop.operation(operation["id"])["expiry"]["status"] == "queued"
    workshop.process_operations(probe)  # the unblock is applied and observed

    expiry = workshop.operation(operation["id"])["expiry"]
    assert expiry["unblock_operation"]["action"] == "unblock"
    assert expiry["unblock_operation"]["status"] == "observed"
    assert workshop.state()["waf"] == [] and probe(ATTACKER) == 200
    assert {"ttl_block_observed", "ttl_expired"} <= steps(workshop)
    assert "C3" in progress.get(workshop.store)["done"]


def test_c3_ttl_expiry_superseded_by_a_later_block(workshop, probe, clock):
    workshop.start("C3")
    temporary = block(workshop, probe, ATTACKER, key="temp", ttl_seconds=10)
    block(workshop, probe, ATTACKER, key="permanent")
    clock.advance(11)
    workshop.process_operations(probe)
    workshop.process_operations(probe)
    assert workshop.operation(temporary["id"])["expiry"]["status"] == "superseded"
    assert workshop.state()["waf"] == [ATTACKER]
    assert "ttl_expired" not in steps(workshop)


def test_ttl_expiry_from_an_old_run_does_not_unblock(workshop, probe, clock):
    workshop.start("C3")
    temporary = block(workshop, probe, ATTACKER, ttl_seconds=10)
    workshop.start("C3")
    clock.advance(11)
    workshop.process_operations(probe)
    assert workshop.store.get("expiry#" + temporary["id"])["status"] == "superseded"
    assert workshop.state()["pending"] == []


# --- alerts ------------------------------------------------------------------

def alert(workshop, ip=ATTACKER, nested=False, **extra):
    result = {"run_id": workshop.state()["run_id"], "src_ip": ip, "scenario": "scanning", "count": 16, **extra}
    return workshop.alert({"result": result} if nested else result)


def deliver(workshop, ip, at):
    workshop.store.update(alert_key(workshop.state()["run_id"], ip), lambda old: {**old, "status": "delivered", "delivered_at": at})


def test_alert_stored_once_per_run_and_source(workshop):
    workshop.start("B")
    first = alert(workshop)
    again = alert(workshop, nested=True)
    alert(workshop, NAT)
    assert first["payload"] == {"run_id": workshop.state()["run_id"], "src_ip": ATTACKER, "scenario": "scanning", "count": "16",
                                "event_id": first["payload"]["event_id"]}
    assert first["status"] == "pending" and first["generation"] == 0
    assert again["payload"]["event_id"] == first["payload"]["event_id"] and again["generation"] == 0
    assert sorted(a["payload"]["src_ip"] for a in workshop.alerts()) == [ATTACKER, NAT]


def test_alert_for_stale_run_rejected(workshop):
    old = workshop.start("B")["run_id"]
    workshop.start("B")
    with pytest.raises(Rejected):
        workshop.alert({"run_id": old, "src_ip": ATTACKER})


def test_alerts_listing_only_current_run(workshop):
    workshop.start("B")
    alert(workshop)
    workshop.start("B")
    assert workshop.alerts() == []


def test_alert_payload_fields_are_bounded(workshop):
    workshop.start("B")
    saved = alert(workshop, scenario="x" * 5000, extra="ignored")
    assert len(saved["payload"]["scenario"]) == 2000 and "extra" not in saved["payload"]


def test_realert_after_cadence_when_delivered_unhandled_unblocked(workshop, clock):
    workshop.start("B")
    first = alert(workshop)
    deliver(workshop, ATTACKER, clock.now)

    clock.advance(119)
    assert alert(workshop)["status"] == "delivered"

    clock.advance(1)
    realert = alert(workshop)
    assert realert["status"] == "pending" and realert["generation"] == 1 and realert["attempts"] == 0
    assert realert["payload"]["event_id"] != first["payload"]["event_id"]
    assert realert["created_at"] == clock.now


def test_no_realert_while_still_pending(workshop, clock):
    workshop.start("B")
    alert(workshop)
    clock.advance(500)
    assert alert(workshop)["generation"] == 0


def test_no_realert_once_handled(workshop, clock):
    workshop.start("B")
    alert(workshop)
    deliver(workshop, ATTACKER, clock.now)
    workshop.action(request(workshop))  # a remediation counts as an outcome
    assert workshop.store.get(alert_key(workshop.state()["run_id"], ATTACKER))["handled_at"]
    clock.advance(500)
    assert alert(workshop)["generation"] == 0


def test_no_realert_once_blocked(workshop, probe, clock):
    workshop.start("B")
    alert(workshop)
    block(workshop, probe, ATTACKER)
    workshop.store.update(alert_key(workshop.state()["run_id"], ATTACKER), lambda old: {**old, "handled_at": None})
    deliver(workshop, ATTACKER, clock.now)
    clock.advance(500)
    assert alert(workshop)["generation"] == 0


def test_realert_cadence_is_configurable(workshop, clock):
    workshop.config["realert_seconds"] = 5
    workshop.start("B")
    alert(workshop)
    deliver(workshop, ATTACKER, clock.now)
    clock.advance(5)
    assert alert(workshop)["generation"] == 1


def test_vpn_alert_waits_for_evidence_only_when_vpn_is_active(workshop):
    workshop.start("C1")
    assert alert(workshop, VPN)["evidence_status"] == "waiting"
    assert "evidence_status" not in alert(workshop, ATTACKER)
    workshop.start("B")
    assert "evidence_status" not in alert(workshop, VPN)


# --- audit -------------------------------------------------------------------

def audit(workshop, event_id, decision="block", kind="verdict"):
    return workshop.audit({"run_id": workshop.state()["run_id"], "event_id": event_id, "kind": kind, "decision": decision,
                           "reasoning": "because", "evidence": []})


def test_audit_marks_matching_alert_handled_and_emits_once(workshop, events):
    workshop.start("C1")
    vpn = alert(workshop, VPN)
    other = alert(workshop, ATTACKER)
    event = audit(workshop, vpn["payload"]["event_id"] + ":AI Agent", decision="allow")
    again = audit(workshop, vpn["payload"]["event_id"] + ":AI Agent", decision="allow")

    assert event["event_id"] == again["event_id"] != vpn["payload"]["event_id"]
    assert event["source"] == "audit" and event["decision"] == "allow"
    assert [e["event_id"] for e in events if e["source"] == "audit"] == [event["event_id"]]
    run_id = workshop.state()["run_id"]
    assert workshop.store.get(alert_key(run_id, VPN))["handled_at"]
    assert not workshop.store.get(alert_key(run_id, other["payload"]["src_ip"]))["handled_at"]
    assert "allow_audited" in steps(workshop)


def test_audit_other_decision_or_kind_is_separate(workshop, events):
    workshop.start("B")
    audit(workshop, "e1")
    audit(workshop, "e1", kind="other")
    assert len([e for e in events if e["source"] == "audit"]) == 2
    assert "allow_audited" not in steps(workshop)


def test_audit_for_stale_run_rejected(workshop):
    old = workshop.start("B")["run_id"]
    workshop.start("B")
    with pytest.raises(Rejected):
        workshop.audit({"run_id": old, "event_id": "e", "kind": "verdict", "decision": "allow"})


# --- approvals ---------------------------------------------------------------

def register(workshop, url="http://localhost:5678/form-waiting/123", ip=NAT):
    return workshop.register_approval(url, workshop.state()["run_id"], ip)


@pytest.mark.parametrize("url", ["http://localhost:5678/form-waiting/123", "http://localhost:5678/webhook-waiting/abc?x=1"])
def test_register_approval_accepts_n8n_waiting_links(workshop, url):
    workshop.start("C2")
    alert(workshop, NAT)
    approval = register(workshop, url)
    assert approval["status"] == "pending" and approval["url"] == url and approval["src_ip"] == NAT
    assert len(approval["id"]) >= 24
    assert [a["id"] for a in workshop.approvals()] == [approval["id"]]
    assert workshop.store.get(alert_key(workshop.state()["run_id"], NAT))["handled_at"]
    assert "approval_registered" in steps(workshop)


@pytest.mark.parametrize("url", [
    "https://localhost:5678/form-waiting/123",
    "http://localhost:5679/form-waiting/123",
    "http://evil.example/form-waiting/123",
    "http://user@localhost:5678/form-waiting/123",
    "http://localhost:5678/rest/workflows",
    "http://localhost:5678/form/123",
    "javascript:alert(1)",
])
def test_register_approval_rejects_other_links(workshop, url):
    workshop.start("C2")
    with pytest.raises(Rejected, match="n8n waiting form"):
        register(workshop, url)
    assert workshop.approvals() == []


def test_register_approval_rejects_dot_segment_escape(workshop):
    workshop.start("C2")
    with pytest.raises(Rejected):
        register(workshop, "http://localhost:5678/form-waiting/../home/workflows")


def test_register_approval_for_stale_run_rejected(workshop):
    old = workshop.start("C2")["run_id"]
    workshop.start("C2")
    with pytest.raises(Rejected):
        workshop.register_approval("http://localhost:5678/form-waiting/1", old, NAT)


def test_approval_validates_exactly_once(workshop):
    workshop.start("C2")
    approval = register(workshop)
    assert workshop.decide_approval(approval["id"], approved=True)["status"] == "approved"
    with pytest.raises(Rejected, match="already used"):
        workshop.decide_approval(approval["id"], approved=True)
    with pytest.raises(Rejected, match="already used"):
        workshop.decide_approval(approval["id"], approved=False)
    assert workshop.approvals() == []
    assert NAT in progress.get(workshop.store)["approved_ips"]
    assert "approval_consumed" in steps(workshop)


def test_approval_deny(workshop):
    workshop.start("C2")
    approval = register(workshop)
    assert workshop.decide_approval(approval["id"], approved=False)["status"] == "denied"
    assert workshop.approval(approval["id"])["status"] == "denied"
    assert progress.get(workshop.store)["approved_ips"] == []
    assert "approval_consumed" not in steps(workshop)


def test_unknown_or_stale_approval_rejected(workshop):
    workshop.start("C2")
    with pytest.raises(Rejected, match="not found"):
        workshop.approval("missing")
    approval = register(workshop)
    workshop.start("C2")
    with pytest.raises(Rejected, match="stale"):
        workshop.approval(approval["id"])
    with pytest.raises(Rejected):
        workshop.decide_approval(approval["id"], approved=True)


def test_block_after_approval(workshop, probe):
    workshop.start("C2")
    approval = register(workshop, ip=ATTACKER)
    block(workshop, probe, NAT, key="unapproved")
    assert "block_after_approval" not in steps(workshop)
    workshop.decide_approval(approval["id"], approved=True)
    block(workshop, probe, ATTACKER, key="approved")
    assert {"approval_registered", "approval_consumed", "block_after_approval"} <= steps(workshop)
