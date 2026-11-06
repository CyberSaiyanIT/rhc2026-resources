"""Simulated threat-intelligence services. Responses always say they are simulated."""
import json
from functools import lru_cache
from importlib.resources import files


@lru_cache
def _fixtures():
    return json.loads(files("romhack").joinpath("data/intelligence.json").read_text())


def lookup(ip, kind):
    fixtures = _fixtures()
    profile = fixtures["profiles"].get(ip)
    if profile and profile.get("http_status") == 503:
        raise RuntimeError("Simulated intelligence outage")
    if not profile:
        return {"ip": ip, "simulated": True, "fixture_version": fixtures["fixture_version"], "status": "unknown"}
    fields = ("score", "reports", "report_context") if kind == "reputation" else ("network", "scanner", "shared_nat")
    return {"ip": ip, "simulated": True, "fixture_version": fixtures["fixture_version"], "status": "ok", **{key: profile[key] for key in fields if key in profile}}
