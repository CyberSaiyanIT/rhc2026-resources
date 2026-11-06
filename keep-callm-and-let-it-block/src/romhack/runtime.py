"""Workshop state: the current run, the simulated WAF blocklist, remediation
operations, alerts, approvals and audit events. Everything lives in one store."""
import hashlib
import ipaddress
import logging
import posixpath
import secrets
import time
import uuid
from urllib.parse import urlparse

from . import progress
from .scenarios import CLIENTS, SCENARIO_IPS, VPN_IP, active_ips

LOG = logging.getLogger(__name__)

PHASES = ("Base", "A", "B", "C1", "C2", "C3")
LAB = "lab"


class Rejected(ValueError):
    pass


class InvalidRequest(Rejected):
    pass


class NotFound(Rejected):
    pass


def alert_key(run_id, src_ip):
    return "alert#" + hashlib.sha256(f"{run_id}:{src_ip}".encode()).hexdigest()


def _event_id(run_id, src_ip, generation=0):
    base = hashlib.sha256(f"{run_id}:{src_ip}".encode()).hexdigest()
    return base if not generation else hashlib.sha256(f"{base}:{generation}".encode()).hexdigest()


def _hook(description, function, *args):
    """Progress is a convenience: never let it break a participant request."""
    try:
        function(*args)
    except Exception:
        LOG.exception("Progress hook failed: %s", description)


class Workshop:
    def __init__(self, config, store, sink=None):
        # ``sink`` receives events bound for Splunk (a list of dicts).
        self.config, self.store = config, store
        self.sink = sink or (lambda events: None)

    # --- run lifecycle -------------------------------------------------
    def state(self):
        return self.store.get(LAB) or {"run_id": "", "phase": "Base", "running": False, "waf": [], "blocks": {},
                                       "pending": [], "history": [], "traffic_offset": 0, "observations": {}}

    def ready(self, run_id):
        state = self.state()
        if not run_id or state["run_id"] != run_id:
            raise Rejected("Run is stale: this alert belongs to an earlier run. Wait for a fresh alert.")
        return state

    def start(self, phase=None):
        """Start (or restart) a phase: clear every block and replay the scenario under a new run ID."""
        if phase is not None and phase not in PHASES:
            raise Rejected("Unknown phase")
        run_id = uuid.uuid4().hex
        def change(old):
            state = old or self.state()
            return {**state, "run_id": run_id, "phase": phase or state["phase"], "running": True, "started_at": time.time(),
                    "waf": [], "blocks": {}, "pending": [], "history": [], "traffic_offset": 0, "observations": {}}
        state = self.store.update(LAB, change)
        _hook("new run", progress.new_run, self.store, run_id, state["phase"])
        return state

    def stop(self):
        return self.store.update(LAB, lambda old: {**(old or self.state()), "running": False})

    # --- remediation ---------------------------------------------------
    def action(self, request):
        state = self.ready(request["run_id"])
        action, ip = request["action"], request["src_ip"]
        if action not in ("block", "unblock"):
            raise Rejected("Expected block or unblock")
        try:
            address = str(ipaddress.IPv4Address(ip))
        except ValueError as exc:
            raise InvalidRequest("Expected a valid IPv4 address") from exc
        if address not in SCENARIO_IPS:
            raise Rejected("IP is outside the workshop scenario")
        ttl = request.get("ttl_seconds")
        if ttl is not None and (state["phase"] != "C3" or action != "block" or not 10 <= ttl <= 600):
            raise Rejected("TTL is available only for C3 blocks, between 10 and 600 seconds")
        key = request.get("idempotency_key") or ""
        if not key or len(key) > 128:
            raise Rejected("A bounded idempotency key is required")
        operation_id = hashlib.sha256(f"{request['run_id']}:{key}".encode()).hexdigest()
        operation = {"id": operation_id, "run_id": state["run_id"], "action": action, "src_ip": address,
                     "status": "queued", "created_at": time.time(), "ttl_seconds": ttl}
        saved = self.store.update("operation#" + operation_id, lambda old: old or operation)
        if any(saved.get(field) != operation.get(field) for field in ("action", "src_ip", "ttl_seconds")):
            raise Rejected("Idempotency key already used for another action")
        self.mark_alert_handled(request["run_id"], address)
        if action == "block":
            _hook("block requested", progress.mark, self.store, request["run_id"], "block_requested")
        def enqueue(old):
            if old["run_id"] != request["run_id"]:
                raise Rejected("Run changed")
            if not any(op["id"] == operation_id for op in old["pending"] + old["history"]):
                if len(old["pending"]) >= 64:
                    raise Rejected("Action queue is full")
                old["pending"].append(saved)
            return old
        self.store.update(LAB, enqueue)
        return self.operation(operation_id)

    def operation(self, operation_id):
        saved = self.store.get("operation#" + operation_id)
        if not saved:
            return None
        result = {**saved, "is_current_run": saved["run_id"] == self.state()["run_id"]}
        if saved.get("ttl_seconds"):
            expiry = self.store.get("expiry#" + operation_id)
            result["expiry"] = None
            if expiry:
                unblock_id = hashlib.sha256(f"{saved['run_id']}:expiry-{operation_id}".encode()).hexdigest()
                result["expiry"] = {"status": expiry["status"], "expires_at": expiry["expires_at"],
                                    "unblock_operation": self.store.get("operation#" + unblock_id)}
        return result

    def process_operations(self, probe):
        """Apply queued operations to the simulated WAF, then confirm each one is
        observed at the website (403 for a block, 200 for an unblock)."""
        state = self.state()
        for operation in list(state["pending"]):
            if operation["status"] == "queued":
                self._apply(operation)
                operation = {**operation, "status": "applied"}
            if probe(operation["src_ip"]) != (403 if operation["action"] == "block" else 200):
                continue
            if operation.get("ttl_seconds"):
                self.store.update("expiry#" + operation["id"], lambda old, op=operation: old or {"operation": op, "expires_at": time.time() + op["ttl_seconds"], "status": "pending"})
            self._complete(operation)
        self._expire()

    def _apply(self, operation):
        def change(old):
            if old["run_id"] != operation["run_id"]:
                return old
            waf = set(old["waf"])
            if operation["action"] == "block":
                waf.add(operation["src_ip"])
                old["blocks"][operation["src_ip"]] = operation["id"]
            else:
                waf.discard(operation["src_ip"])
                old["blocks"].pop(operation["src_ip"], None)
            old["waf"] = sorted(waf)
            for item in old["pending"]:
                if item["id"] == operation["id"]:
                    item["status"] = "applied"
            return old
        self.store.update(LAB, change)
        self.store.update("operation#" + operation["id"], lambda old: {**(old or operation), "status": "applied"})

    def _complete(self, operation):
        now = time.time()
        def change(old):
            if old["run_id"] == operation["run_id"] and any(op["id"] == operation["id"] for op in old["pending"]):
                old["pending"] = [op for op in old["pending"] if op["id"] != operation["id"]]
                old["history"] = (old["history"] + [{**operation, "status": "observed", "completed_at": now}])[-30:]
            return old
        self.store.update(LAB, change)
        self.store.update("operation#" + operation["id"], lambda old: {**(old or operation), "status": "observed", "completed_at": now})
        self.sink([{"source": "audit", "event_id": "lifecycle-" + operation["id"], "run_id": operation["run_id"], "timestamp": now,
                    "kind": "remediation", "action": operation["action"], "src_ip": operation["src_ip"], "decision": "observed",
                    "operation_id": operation["id"]}])
        run_id, ip = operation["run_id"], operation["src_ip"]
        self.mark_alert_handled(run_id, ip)
        current = progress.get(self.store)
        if operation["action"] == "block":
            if CLIENTS.get(ip, {}).get("attacker"):
                _hook("attacker blocked", progress.mark, self.store, run_id, "attacker_blocked")
            if ip in current.get("approved_ips", []):
                _hook("block after approval", progress.mark, self.store, run_id, "block_after_approval")
            if operation.get("ttl_seconds"):
                _hook("ttl ip", progress.add_ttl_ip, self.store, run_id, ip)
                _hook("ttl block", progress.mark, self.store, run_id, "ttl_block_observed")
        elif ip in current.get("ttl_ips", []):
            _hook("ttl expired", progress.mark, self.store, run_id, "ttl_expired")

    def _expire(self):
        for key, expiry in self.store.list("expiry#"):
            if expiry["status"] != "pending" or expiry["expires_at"] > time.time():
                continue
            operation = expiry["operation"]
            if self.state()["blocks"].get(operation["src_ip"]) != operation["id"]:
                self.store.update(key, lambda old: {**old, "status": "superseded"})
                continue
            try:
                self.action({"run_id": operation["run_id"], "action": "unblock", "src_ip": operation["src_ip"], "idempotency_key": "expiry-" + operation["id"]})
                status = "queued"
            except Rejected:
                status = "stale"
            self.store.update(key, lambda old, status=status: {**old, "status": status})

    # --- alerts --------------------------------------------------------
    def alert(self, result):
        """Accept a Splunk detection. One investigation per source and run; an
        unhandled, unblocked source is re-delivered every ``realert_seconds``."""
        if isinstance(result.get("result"), dict):
            result = result["result"]
        run_id, src_ip = result.get("run_id"), result.get("src_ip")
        state = self.ready(run_id)
        now = time.time()
        realert = float(self.config.get("realert_seconds", 120))
        def change(old):
            if old:
                due = old["status"] == "delivered" and not old.get("handled_at") and now - (old.get("delivered_at") or 0) >= realert
                if not due or src_ip in self.state()["blocks"]:
                    return old
                generation = old.get("generation", 0) + 1
                return {**old, "payload": {**old["payload"], "event_id": _event_id(run_id, src_ip, generation)}, "status": "pending",
                        "attempts": 0, "generation": generation, "delivered_at": None, "created_at": now}
            payload = {name: str(result.get(name, ""))[:2000] for name in ("run_id", "src_ip", "scenario", "count")}
            payload["event_id"] = _event_id(run_id, src_ip)
            waiting = {"evidence_status": "waiting", "evidence_attempts": 0} if src_ip == VPN_IP and VPN_IP in active_ips(state["phase"]) else {}
            return {"payload": payload, "status": "pending", "attempts": 0, "generation": 0, "delivered_at": None, "handled_at": None, "created_at": now, **waiting}
        return self.store.update(alert_key(run_id, src_ip), change)

    def mark_alert_handled(self, run_id, src_ip):
        """The workflow produced an outcome for this source: stop re-delivering it."""
        def change(old):
            if old and old["payload"]["run_id"] == run_id and not old.get("handled_at"):
                return {**old, "handled_at": time.time()}
            return old
        if self.store.get(alert_key(run_id, src_ip)):
            self.store.update(alert_key(run_id, src_ip), change)

    def alerts(self, limit=10):
        run_id = self.state()["run_id"]
        items = [value for _, value in self.store.list("alert#") if value["payload"]["run_id"] == run_id]
        return sorted(items, key=lambda value: value.get("created_at", 0))[-limit:]

    # --- audit ---------------------------------------------------------
    def audit(self, payload):
        state = self.ready(payload["run_id"])
        # Without an event_id every audit call is its own record.
        payload = {**payload, "event_id": payload.get("event_id") or uuid.uuid4().hex, "kind": payload.get("kind") or "workflow"}
        key = hashlib.sha256(f"{payload['run_id']}:{payload['event_id']}:{payload['kind']}".encode()).hexdigest()
        event = {**payload, "event_id": key, "source": "audit", "timestamp": time.time()}
        if not self.store.get("audit#" + key):
            self.store.update("audit#" + key, lambda old: old or event)
            self.sink([event])
        if payload.get("decision") == "allow":
            _hook("allow audited", progress.mark, self.store, payload["run_id"], "allow_audited")
        if payload.get("src_ip") in SCENARIO_IPS:
            self.mark_alert_handled(payload["run_id"], payload["src_ip"])
        # Reference workflows audit with event_id "<alert event_id>:<node name>".
        for ip in active_ips(state["phase"]):
            existing = self.store.get(alert_key(payload["run_id"], ip))
            if existing and str(payload["event_id"]).startswith(existing["payload"]["event_id"]):
                self.mark_alert_handled(payload["run_id"], ip)
        return event

    # --- approvals -----------------------------------------------------
    def register_approval(self, url, run_id, src_ip):
        self.ready(run_id)
        if src_ip not in SCENARIO_IPS:
            raise Rejected("IP is outside the workshop scenario")
        expected, actual = urlparse(self.config["n8n_public_url"]), urlparse(url)
        path = posixpath.normpath(actual.path) if actual.path else ""
        if (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc) or actual.username or path != actual.path or not path.startswith(("/form-waiting/", "/webhook-waiting/")):
            raise Rejected("Approval link must be an n8n waiting form on " + self.config["n8n_public_url"])
        approval_id = secrets.token_urlsafe(24)
        self.mark_alert_handled(run_id, src_ip)
        _hook("approval registered", progress.mark, self.store, run_id, "approval_registered")
        return self.store.update("approval#" + approval_id, lambda old: {"id": approval_id, "url": url, "run_id": run_id, "src_ip": src_ip, "status": "pending", "created_at": time.time()})

    def approval(self, approval_id):
        item = self.store.get("approval#" + approval_id)
        if not item:
            raise NotFound("Approval not found")
        self.ready(item["run_id"])
        return item

    def decide_approval(self, approval_id, approved):
        """Consume a pending approval exactly once."""
        item = self.approval(approval_id)
        def use(old):
            if old["status"] != "pending":
                raise Rejected("Approval already used")
            return {**old, "status": "approved" if approved else "denied"}
        result = self.store.update("approval#" + approval_id, use)
        if approved:
            _hook("approval consumed", progress.approval_consumed, self.store, item["run_id"], item["src_ip"])
        return result

    def approvals(self):
        run_id = self.state()["run_id"]
        return [value for _, value in self.store.list("approval#") if value["run_id"] == run_id and value["status"] == "pending"]
