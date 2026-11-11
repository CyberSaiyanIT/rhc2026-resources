"""Splunk access: HTTP Event Collector for logs, REST search for the agent tool."""
import json
import logging
import threading
import time
from collections import deque

import httpx

LOG = logging.getLogger(__name__)

INDEX = "romhack"


class QueryError(ValueError):
    """Splunk rejected the SPL itself; the message says why."""


# Splunk bookkeeping fields that only cost the agent tokens.
NOISE = ("_bkt", "_cd", "_si", "_serial", "_indextime", "_sourcetype", "_eventtype_color", "splunk_server",
         "linecount", "punct", "timestartpos", "timeendpos", "eventtype", "tag", "host", "source", "index")


def normalize(spl):
    """Accept SPL the way Splunk's search bar does: an implicit leading ``search``."""
    spl = spl.strip()
    return spl if spl.startswith("|") or spl.split(None, 1)[0].lower() == "search" else "search " + spl


def scope(spl, run_id):
    """Limit an ordinary search to one run, so a query can never mix in older runs."""
    spl = normalize(spl)
    if not run_id or spl.startswith("|"):
        return spl
    return f'search run_id="{run_id}" ' + spl.split(None, 1)[1] if " " in spl else f'search run_id="{run_id}"'


def slim(row):
    """Keep the fields an analyst reads. Workshop events are JSON, so a raw event
    is unpacked into its fields instead of shipping the whole _raw string."""
    kept = {key: value for key, value in row.items() if key not in NOISE and not key.startswith("date_") and (key in ("_time", "_raw") or not key.startswith("_"))}
    try:
        event = json.loads(kept["_raw"]) if "_raw" in kept else None
    except ValueError:
        event = None
    if isinstance(event, dict):
        kept.pop("_raw")
        kept = {**{key: value for key, value in event.items() if key not in ("timestamp", "source")}, **kept}
    return kept


class Hec:
    """Buffers events and ships them to Splunk in the background. Events wait
    in memory while Splunk is still starting; the oldest are dropped past ``limit``."""

    def __init__(self, config, limit=20_000):
        self.config = config
        self.buffer = deque(maxlen=limit)
        self.lock = threading.Lock()

    def __call__(self, events):
        with self.lock:
            self.buffer.extend(events)

    def flush(self, http=None):
        with self.lock:
            batch = [self.buffer.popleft() for _ in range(min(500, len(self.buffer)))]
        if not batch:
            return 0
        body = "\n".join(json.dumps({"index": INDEX, "sourcetype": "romhack:" + event["source"], "time": event["timestamp"], "event": event}) for event in batch)
        try:
            client = http or httpx.Client(timeout=10)
            try:
                response = client.post(self.config["splunk_hec_url"].rstrip("/") + "/services/collector/event",
                                       headers={"Authorization": "Splunk " + self.config["splunk_hec_token"]}, content=body)
                response.raise_for_status()
            finally:
                if http is None:
                    client.close()
        except httpx.HTTPError:
            with self.lock:
                self.buffer.extendleft(reversed(batch))
            raise
        return len(batch)

    def run(self, stop):
        waiting = False
        while not stop.is_set():
            try:
                sent = self.flush()
                if waiting:
                    LOG.info("Splunk HEC is reachable; log delivery resumed")
                waiting = False
                stop.wait(0.05 if sent >= 500 else 1)
            except httpx.HTTPError:
                if not waiting:
                    LOG.info("Waiting for Splunk HEC (Splunk takes a few minutes to start)")
                waiting = True
                stop.wait(5)


def _client(**kwargs):
    # Splunk's management port uses its own self-signed certificate.
    return httpx.Client(verify=False, **kwargs)


def ensure_analyst(config, http=None):
    """Create the read-only ``analyst`` user the search tool runs as. Idempotent."""
    owned = http is None
    http = http or _client(timeout=15)
    try:
        base = config["splunk_api_url"].rstrip("/")
        admin = ("admin", config["splunk_admin_password"])
        user = config["splunk_analyst_user"]
        found = http.get(f"{base}/services/authentication/users/{user}", auth=admin, params={"output_mode": "json"})
        if found.status_code == 200:
            return False
        if found.status_code != 404:
            found.raise_for_status()
        created = http.post(f"{base}/services/authentication/users", auth=admin,
                            data={"name": user, "password": config["splunk_analyst_password"], "roles": "romhack_analyst", "output_mode": "json"})
        created.raise_for_status()
        return True
    finally:
        if owned:
            http.close()


def search(config, spl, run_id=None, earliest="-15m", max_time=20, count=100, http=None):
    """Run SPL as the analyst user, limited to ``run_id`` when given; returns the result rows."""
    owned = http is None
    http = http or _client(timeout=max_time + 15)
    try:
        response = http.post(config["splunk_api_url"].rstrip("/") + "/services/search/jobs/export",
                             auth=(config["splunk_analyst_user"], config["splunk_analyst_password"]),
                             data={"search": scope(spl, run_id), "earliest_time": earliest, "latest_time": "now", "max_time": str(max_time), "count": str(count), "output_mode": "json"})
        if response.status_code == 401:
            ensure_analyst(config, http=None if owned else http)
        if response.status_code == 400:
            try:
                messages = response.json().get("messages", [])
            except ValueError:
                messages = []
            raise QueryError("Splunk rejected the search: " + ("; ".join(m.get("text", "") for m in messages) or response.text[:300]))
        response.raise_for_status()
        rows = []
        for line in response.text.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError("Splunk returned an unexpected response") from exc
            if any(message.get("type") in ("ERROR", "FATAL") for message in item.get("messages", [])):
                raise RuntimeError("; ".join(message.get("text", "") for message in item["messages"]))
            if "result" in item and item.get("preview") is not True:
                rows.append(slim(item["result"]))
                if len(rows) >= count:
                    break
        return rows
    finally:
        if owned:
            http.close()


def vpn_evidence_ready(config, run_id, src_ip, http=None):
    """True once the VPN client's failed logins, successful login and later
    authenticated use are all indexed, so the agent never investigates half a story."""
    spl = (
        f'search index={INDEX} run_id="{run_id}" src_ip="{src_ip}" sourcetype=romhack:web synthetic_user!="" synthetic_session!=""'
        " | dedup event_id | sort 0 timestamp"
        ' | streamstats count(eval(auth_outcome="failure" AND status=401)) as preceding_failures by synthetic_user synthetic_session'
        ' | stats max(eval(if(auth_outcome="success" AND status=200,preceding_failures,0))) as failures'
        ' min(eval(if(auth_outcome="success" AND status=200,timestamp,null()))) as success_at'
        ' max(eval(if(application_event="authenticated_use" AND status=200,timestamp,null()))) as use_at by synthetic_user synthetic_session'
        " | where failures>=5 AND use_at>success_at | head 1 | eval evidence_ready=1 | fields evidence_ready"
    )
    rows = search(config, spl, run_id=run_id, earliest="0", max_time=5, count=1, http=http)
    return any(str(row.get("evidence_ready")) == "1" for row in rows)


def wait_until(predicate, stop, interval=10):
    while not stop.is_set():
        try:
            if predicate():
                return True
        except Exception:
            pass
        stop.wait(interval)
    return False
