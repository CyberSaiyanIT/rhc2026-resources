"""Per-phase checklist shown in the portal. A cache derived from workshop facts:
safe to lose, and callers never let a failure here break a request."""
import time

# Ordered (step, required) pairs per phase. Required steps complete the phase.
STEPS = {
    "Base": [("alert_delivered", True)],
    "A": [("alert_delivered", False), ("block_requested", False), ("attacker_blocked", True)],
    "B": [("alert_delivered", False), ("attacker_blocked", False), ("green_held", True)],
    "C1": [("alert_delivered", False), ("allow_audited", True), ("green_held", True)],
    "C2": [("alert_delivered", False), ("approval_registered", False), ("approval_consumed", True),
           ("block_after_approval", True), ("green_held", True)],
    "C3": [("alert_delivered", False), ("ttl_block_observed", True), ("ttl_expired", True)],
}

LABELS = {
    "alert_delivered": "An alert reached your workflow",
    "block_requested": "Your workflow requested a block",
    "attacker_blocked": "Frieza (the attacker) is blocked",
    "green_held": "Production light stayed green",
    "allow_audited": "The AI verdict allowed a legitimate client",
    "approval_registered": "An approval request appeared in the portal",
    "approval_consumed": "A human approved a block",
    "block_after_approval": "The approved block was enforced",
    "ttl_block_observed": "A temporary block was enforced",
    "ttl_expired": "The temporary block expired by itself",
}

KEY = "progress"


def _blank():
    return {"phase": "Base", "run_id": "", "steps": {}, "done": {}, "green_streak": 0, "ttl_ips": [], "approved_ips": []}


def get(store):
    return store.get(KEY) or _blank()


def checklist(store):
    value = get(store)
    return [{"step": step, "label": LABELS[step], "required": required, "done": step in value["steps"]}
            for step, required in STEPS.get(value["phase"], [])]


def _complete_if_ready(value, now):
    required = [step for step, needed in STEPS.get(value["phase"], []) if needed]
    if required and value["phase"] not in value["done"] and all(step in value["steps"] for step in required):
        value["done"] = {**value["done"], value["phase"]: now}
    return value


def _change(store, run_id, edit):
    now = time.time()
    def change(old):
        value = {**_blank(), **(old or {})}
        if value["run_id"] != run_id:
            return value
        return _complete_if_ready(edit(value, now) or value, now)
    return store.update(KEY, change)


def new_run(store, run_id, phase):
    """Phase completion marks survive a replay; everything else restarts."""
    def change(old):
        return {**_blank(), "done": (old or {}).get("done", {}), "phase": phase, "run_id": run_id}
    return store.update(KEY, change)


def mark(store, run_id, step):
    def edit(value, now):
        value["steps"].setdefault(step, now)
    return _change(store, run_id, edit)


def add_ttl_ip(store, run_id, ip):
    def edit(value, now):
        if ip not in value["ttl_ips"]:
            value["ttl_ips"].append(ip)
    return _change(store, run_id, edit)


def approval_consumed(store, run_id, src_ip):
    def edit(value, now):
        if src_ip not in value["approved_ips"]:
            value["approved_ips"].append(src_ip)
        value["steps"].setdefault("approval_consumed", now)
    return _change(store, run_id, edit)


def green_sample(store, run_id, color):
    """Two consecutive green production samples hold the light."""
    def edit(value, now):
        value["green_streak"] = value["green_streak"] + 1 if color == "green" else 0
        if value["green_streak"] >= 2:
            value["steps"].setdefault("green_held", now)
    return _change(store, run_id, edit)
