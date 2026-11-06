"""Background loops: scenario traffic, alert delivery, evidence readiness,
remediation enforcement and the production light. Each runs in its own thread."""
import logging
import threading
import time

import httpx

from . import progress, splunk
from .production import sample_once
from .runtime import Rejected
from .scenarios import VPN_IP, active_ips, requests as scenario_requests

LOG = logging.getLogger(__name__)


class Probe:
    """Ask the website whether a scenario client can currently connect."""

    def __init__(self, config, http=None):
        self.url = config["target_url"].rstrip("/") + "/"
        self.http = http or httpx.Client(timeout=3)

    def __call__(self, ip):
        try:
            return self.http.get(self.url, headers={"X-Romhack-Client-IP": ip, "X-Romhack-Run-ID": "verification"}).status_code
        except httpx.HTTPError:
            return None


def traffic_once(workshop, http):
    """Send the next batch of scenario requests. The scenario repeats until the
    next start/stop, so blocks applied later are visible in later traffic."""
    state = workshop.state()
    if not state.get("running"):
        return
    sequence = scenario_requests(state["phase"])
    offset = state["traffic_offset"]
    # The 8-request VPN login story goes first so C1 does not wait for the cycle.
    size = 8 if offset == 0 and VPN_IP in active_ips(state["phase"]) else int(workshop.config["traffic_requests_per_pass"])
    def advance(old):
        if old["run_id"] != state["run_id"] or old["traffic_offset"] != offset:
            raise Rejected("Traffic batch already sent")
        return {**old, "traffic_offset": offset + size}
    try:
        workshop.store.update("lab", advance)
    except Rejected:
        return
    base = workshop.config["target_url"].rstrip("/")
    for index in range(offset, offset + size):
        ip, method, path, context = sequence[index % len(sequence)]
        try:
            http.request(method, base + path, headers={"X-Romhack-Client-IP": ip, "X-Romhack-Run-ID": state["run_id"], **context})
        except httpx.HTTPError:
            LOG.warning("Scenario request to the website failed")


def dispatch_once(workshop, http, now=None):
    """Deliver pending alerts to the n8n webhook, retrying with backoff until the workflow is published."""
    now = time.time() if now is None else now
    for key, event in workshop.store.list("alert#"):
        if event["status"] not in ("pending", "retry") or event.get("next_attempt", 0) > now:
            continue
        payload = event["payload"]
        try:
            workshop.ready(payload["run_id"])
        except Rejected:
            workshop.store.update(key, lambda old: {**old, "status": "stale"})
            continue
        if event.get("evidence_status") in ("waiting", "failed"):
            continue
        try:
            response = http.post(workshop.config["n8n_webhook_url"], json=payload)
            response.raise_for_status()
        except httpx.HTTPError as error:
            attempts = event["attempts"] + 1
            reason = "workflow not published (n8n answered 404)" if isinstance(error, httpx.HTTPStatusError) and error.response.status_code == 404 else str(error)[:200]
            workshop.store.update(key, lambda old: {**old, "attempts": attempts, "status": "retry", "last_error": reason, "next_attempt": now + min(30, 2 ** min(attempts, 5))})
        else:
            workshop.store.update(key, lambda old: {**old, "status": "delivered", "attempts": old["attempts"] + 1, "delivered_at": now, "last_error": ""})
            try:
                progress.mark(workshop.store, payload["run_id"], "alert_delivered")
            except Exception:
                LOG.exception("Progress mark failed")


def evidence_once(workshop, check=None, clock=time.time):
    """Hold the VPN alert until its whole login story is searchable in Splunk."""
    check = check or (lambda run_id, ip: splunk.vpn_evidence_ready(workshop.config, run_id, ip))
    for key, event in workshop.store.list("alert#"):
        if event.get("evidence_status") != "waiting" or event.get("evidence_next_attempt", 0) > clock():
            continue
        payload = event["payload"]
        try:
            workshop.ready(payload["run_id"])
        except Rejected:
            workshop.store.update(key, lambda old: {**old, "status": "stale", "evidence_status": "stale"})
            continue
        attempts = event.get("evidence_attempts", 0) + 1
        if clock() >= event["created_at"] + float(workshop.config["evidence_timeout_seconds"]):
            values = {"evidence_status": "failed", "evidence_error": "Splunk did not index the VPN login evidence in time. Check Splunk, then press Replay."}
        else:
            try:
                ready = check(payload["run_id"], payload["src_ip"])
            except Exception:
                ready = False
            values = {"evidence_status": "ready"} if ready else {"evidence_next_attempt": clock() + min(15, 2 ** min(attempts, 4))}
        workshop.store.update(key, lambda old: {**old, **values, "evidence_attempts": attempts} if old.get("evidence_status") == "waiting" else old)


def _loop(name, step, interval, stop):
    def run():
        while not stop.is_set():
            try:
                step()
            except Exception:
                LOG.exception("%s pass failed; retrying", name)
            stop.wait(interval())
    return threading.Thread(target=run, name=name, daemon=True)


def start_workers(workshop, hec, stop):
    config = workshop.config
    probe = Probe(config)
    traffic_http, dispatch_http = httpx.Client(timeout=10), httpx.Client(timeout=15)

    def production():
        color = sample_once(workshop, probe)
        if color:
            progress.green_sample(workshop.store, workshop.state()["run_id"], color)

    threads = [
        threading.Thread(target=hec.run, args=(stop,), name="hec", daemon=True),
        threading.Thread(target=lambda: splunk.wait_until(lambda: splunk.ensure_analyst(config) is not None, stop), name="splunk-user", daemon=True),
        _loop("traffic", lambda: traffic_once(workshop, traffic_http), lambda: max(0.2, float(config["traffic_interval_seconds"])), stop),
        _loop("dispatch", lambda: dispatch_once(workshop, dispatch_http), lambda: 2, stop),
        _loop("evidence", lambda: evidence_once(workshop), lambda: 3, stop),
        _loop("operations", lambda: workshop.process_operations(probe), lambda: 1, stop),
        _loop("production", production, lambda: max(1.0, float(config["production_interval_seconds"])), stop),
    ]
    for thread in threads:
        thread.start()
    return threads
