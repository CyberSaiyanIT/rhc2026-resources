"""The production light: observed access through the website, independent of
what the workflow intended. Unknown observations never imply protection."""
import time

from .runtime import alert_key
from .scenarios import CLIENTS, VPN_IP, active_ips


def aggregate(state, observations, *, now=None, freshness_seconds=20):
    now = time.time() if now is None else now
    running = state.get("running") and bool(state.get("run_id"))
    clients = []
    for ip in active_ips(state.get("phase", "Base")):
        sample = observations.get(ip, {})
        fresh = bool(running and sample.get("run_id") == state["run_id"] and 0 <= now - sample.get("sampled_at", 0) < freshness_seconds)
        connectivity = sample.get("connectivity") if fresh and sample.get("connectivity") in ("connected", "blocked") else "unknown"
        clients.append({"ip": ip, **CLIENTS[ip], "connectivity": connectivity})
    blocked = [c["name"] for c in clients if not c["attacker"] and c["connectivity"] == "blocked"]
    if not running:
        color, label, reason = "gray", "Scenario stopped", "Pick a phase and press Start to replay the scenario."
    elif blocked:
        color, label, reason = "red", "Production access disrupted", "Legitimate access blocked: " + ", ".join(blocked) + "."
    elif any(c["connectivity"] == "unknown" for c in clients):
        color, label, reason = "gray", "Production access unknown", "Waiting for fresh observations of every active client."
    elif any(c["attacker"] and c["connectivity"] == "connected" for c in clients):
        color, label, reason = "yellow", "Attack traffic can reach production", "Frieza (the attacker) is not blocked. Legitimate clients are unaffected."
    else:
        color, label, reason = "green", "Production access protected", "Frieza (the attacker) is blocked; all legitimate clients can connect."
    return {"run_id": state.get("run_id"), "phase": state.get("phase"), "color": color, "label": label, "reason": reason, "clients": clients}


def status(workshop, now=None):
    state = workshop.state()
    result = aggregate(state, state.get("observations", {}), now=now, freshness_seconds=float(workshop.config["production_freshness_seconds"]))
    vpn = workshop.store.get(alert_key(state["run_id"], VPN_IP)) or {} if state["run_id"] else {}
    result["evidence_errors"] = [vpn["evidence_error"]] if vpn.get("evidence_status") == "failed" else []
    return result


def sample_once(workshop, probe, clock=time.time):
    state = workshop.state()
    if not state.get("running"):
        return None
    run_id = state["run_id"]
    observations = {}
    for ip in active_ips(state["phase"]):
        code = probe(ip)
        observations[ip] = {"run_id": run_id, "sampled_at": clock(), "connectivity": {200: "connected", 403: "blocked"}.get(code, "unknown")}
    def save(old):
        if old["run_id"] == run_id:
            old["observations"] = observations
        return old
    workshop.store.update("lab", save)
    return status(workshop, now=clock())["color"]
