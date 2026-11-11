import pytest
from conftest import ATTACKER, BENIGN, NAT, VPN, block

from romhack import progress
from romhack.production import aggregate, sample_once

NOW = 1_000.0


def running(phase="B", run_id="r1"):
    return {"run_id": run_id, "phase": phase, "running": True}


def observe(connectivity, run_id="r1", age=1.0):
    return {ip: {"run_id": run_id, "sampled_at": NOW - age, "connectivity": value} for ip, value in connectivity.items()}


ALL_CONNECTED = {ATTACKER: "connected", NAT: "connected", BENIGN: "connected"}


def color(state, observations, **kwargs):
    return aggregate(state, observations, now=NOW, **kwargs)["color"]


@pytest.mark.parametrize("state", [{}, {"run_id": "r1", "phase": "B", "running": False}, {"run_id": "", "phase": "B", "running": True}])
def test_stopped_is_gray(state):
    result = aggregate(state, observe(ALL_CONNECTED), now=NOW)
    assert result["color"] == "gray" and result["label"] == "Scenario stopped"


def test_attacker_reaching_production_is_yellow():
    assert color(running(), observe(ALL_CONNECTED)) == "yellow"


def test_attacker_blocked_and_clients_connected_is_green():
    result = aggregate(running(), observe({**ALL_CONNECTED, ATTACKER: "blocked"}), now=NOW)
    assert result["color"] == "green"
    assert [(c["ip"], c["connectivity"]) for c in result["clients"]] == [(ATTACKER, "blocked"), (NAT, "connected"), (BENIGN, "connected")]


@pytest.mark.parametrize("blocked", [NAT, BENIGN])
def test_blocking_a_legitimate_client_is_red(blocked):
    result = aggregate(running(), observe({**ALL_CONNECTED, ATTACKER: "blocked", blocked: "blocked"}), now=NOW)
    assert result["color"] == "red" and "Legitimate access blocked" in result["reason"]


def test_red_wins_over_unknown():
    assert color(running(), observe({NAT: "blocked"})) == "red"


def test_c1_includes_the_vpn_client():
    observations = observe({**ALL_CONNECTED, ATTACKER: "blocked"})
    assert color(running("C1"), observations) == "gray"
    assert color(running("C1"), {**observations, **observe({VPN: "connected"})}) == "green"
    assert color(running("C1"), {**observations, **observe({VPN: "blocked"})}) == "red"


@pytest.mark.parametrize("observations", [
    {},
    observe({**ALL_CONNECTED, ATTACKER: "blocked"}, age=20),
    observe({**ALL_CONNECTED, ATTACKER: "blocked"}, age=-5),
    observe({**ALL_CONNECTED, ATTACKER: "blocked"}, run_id="old"),
    observe({**ALL_CONNECTED, ATTACKER: "unknown"}),
    observe({**ALL_CONNECTED, ATTACKER: "teapot"}),
])
def test_missing_stale_or_unknown_observations_are_gray(observations):
    result = aggregate(running(), observations, now=NOW)
    assert result["color"] == "gray" and result["label"] == "Production access unknown"


def test_stale_legitimate_block_is_not_red():
    observations = {**observe({ATTACKER: "blocked", BENIGN: "connected"}), **observe({NAT: "blocked"}, age=30)}
    result = aggregate(running(), observations, now=NOW)
    assert result["color"] == "gray"
    assert {c["ip"]: c["connectivity"] for c in result["clients"]}[NAT] == "unknown"


def test_freshness_is_configurable():
    observations = observe({**ALL_CONNECTED, ATTACKER: "blocked"}, age=30)
    assert color(running(), observations, freshness_seconds=60) == "green"


def test_sample_once_when_stopped_is_none(workshop):
    assert sample_once(workshop, lambda ip: 200) is None


def test_sample_once_records_observations(workshop, probe):
    run = workshop.start("B")["run_id"]
    assert sample_once(workshop, probe) == "yellow"
    block(workshop, probe, ATTACKER)
    assert sample_once(workshop, probe, clock=lambda: 5_000.0) == "green"
    observations = workshop.state()["observations"]
    assert {ip: o["connectivity"] for ip, o in observations.items()} == {ATTACKER: "blocked", NAT: "connected", BENIGN: "connected"}
    assert {o["run_id"] for o in observations.values()} == {run}


def test_sample_once_maps_other_codes_to_unknown(workshop):
    workshop.start("B")
    assert sample_once(workshop, lambda ip: None) == "gray"
    assert {o["connectivity"] for o in workshop.state()["observations"].values()} == {"unknown"}


def test_sample_once_ignores_a_run_that_ended_mid_sample(workshop):
    workshop.start("B")
    restarted = []

    def probe(ip):
        if not restarted:
            restarted.append(workshop.start("B")["run_id"])
        return 200

    assert sample_once(workshop, probe) == "gray"
    assert workshop.state()["run_id"] == restarted[0]
    assert workshop.state()["observations"] == {}


def test_two_green_samples_complete_phase_b(workshop, probe):
    run = workshop.start("B")["run_id"]
    block(workshop, probe, ATTACKER)
    progress.green_sample(workshop.store, run, sample_once(workshop, probe))
    assert "green_held" not in progress.get(workshop.store)["steps"]
    progress.green_sample(workshop.store, run, sample_once(workshop, probe))
    assert "green_held" in progress.get(workshop.store)["steps"]
    assert "B" in progress.get(workshop.store)["done"]
    workshop.start("B")
    assert "B" in progress.get(workshop.store)["done"]  # completion survives a replay
    assert progress.get(workshop.store)["steps"] == {}


def test_green_streak_resets_on_other_colors(workshop):
    run = workshop.start("B")["run_id"]
    for value in ("green", "yellow", "green"):
        progress.green_sample(workshop.store, run, value)
    assert "green_held" not in progress.get(workshop.store)["steps"]
    progress.green_sample(workshop.store, "old-run", "green")
    assert "green_held" not in progress.get(workshop.store)["steps"]
