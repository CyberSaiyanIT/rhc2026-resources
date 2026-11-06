"""Shared in-memory wiring: a Workshop on MemoryStore, the simulated website, a
probe through it, and a controllable clock. No network, no docker."""
import importlib
import sys
import types

import pytest
from fastapi.testclient import TestClient

from romhack import runtime
from romhack.config import load_config
from romhack.runtime import Workshop
from romhack.store import MemoryStore
from romhack.target import create_target

ATTACKER, NAT, BENIGN, VPN = "198.51.100.10", "198.51.100.20", "198.51.100.30", "198.51.100.40"


def import_app():
    """Import romhack.app without depending on the portal module, which is
    rendered HTML and tested on its own. The stub is removed again afterwards."""
    if "romhack.app" in sys.modules:
        return sys.modules["romhack.app"]
    previous = sys.modules.get("romhack.portal")
    sys.modules["romhack.portal"] = types.SimpleNamespace(render=lambda config: "<html>portal</html>")
    try:
        return importlib.import_module("romhack.app")
    finally:
        if previous is None:
            sys.modules.pop("romhack.portal", None)
        else:
            sys.modules["romhack.portal"] = previous


class Clock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def config(tmp_path):
    return {**load_config({}), "workflows_dir": str(tmp_path / "workflows")}


@pytest.fixture
def events():
    return []


@pytest.fixture
def workshop(config, events):
    return Workshop(config, MemoryStore(), sink=events.extend)


@pytest.fixture
def clock(monkeypatch):
    """Fake wall clock for romhack.runtime only (alerts, TTL expiry)."""
    fake = Clock()
    monkeypatch.setattr(runtime, "time", types.SimpleNamespace(time=fake))
    return fake


@pytest.fixture
def site(workshop):
    return TestClient(create_target(workshop))


@pytest.fixture
def probe(site):
    def check(ip):
        return site.get("/", headers={"X-Romhack-Client-IP": ip, "X-Romhack-Run-ID": "verification"}).status_code
    return check


def block(workshop, probe, ip, key="block", **extra):
    """Request a block for the current run and let the operations loop enforce it."""
    operation = workshop.action({"action": "block", "src_ip": ip, "run_id": workshop.state()["run_id"], "idempotency_key": key, **extra})
    workshop.process_operations(probe)
    return workshop.operation(operation["id"])
