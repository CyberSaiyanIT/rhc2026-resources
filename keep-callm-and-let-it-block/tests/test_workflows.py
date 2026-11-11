"""The committed workflows/ files match the generator and stay credential-free."""
import json
from pathlib import Path

import pytest

from romhack import workflows

ROOT = Path(__file__).parents[1] / "workflows"
TOOLS = ("Scouter - Reputation Intel", "Scouter - Network Context", "Splunk investigation")


def load(phase):
    return json.loads((ROOT / f"{phase}.json").read_text(encoding="utf-8"))


def keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from keys(item)


def test_files_are_up_to_date(tmp_path):
    workflows.write_checkpoints(tmp_path)
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(f"{phase}.json" for phase in workflows.PHASES)
    for phase in workflows.PHASES:
        assert (ROOT / f"{phase}.json").read_text(encoding="utf-8") == (tmp_path / f"{phase}.json").read_text(encoding="utf-8"), \
            f"workflows/{phase}.json is stale: run `uv run python -m romhack.workflows`"


@pytest.mark.parametrize("phase", workflows.PHASES)
def test_workflow_shape(phase):
    workflow = load(phase)
    assert len(workflow["id"]) == 16 and workflow["id"].isalnum()
    assert workflow["name"] == f"RomHack · {phase}" and workflow["active"] is False
    assert "credentials" not in set(keys(workflow))
    assert "lab_id" not in json.dumps(workflow)
    assert not [node for node in workflow["nodes"] if node["type"].startswith("@n8n/n8n-nodes-langchain.lmChat")]
    # Participants build every phase with built-in nodes: no JavaScript Code node.
    assert not [node["name"] for node in workflow["nodes"] if node["type"] == "n8n-nodes-base.code"]
    webhook = next(node for node in workflow["nodes"] if node["type"] == "n8n-nodes-base.webhook")
    assert webhook["parameters"]["path"] == "romhack" and webhook["parameters"]["httpMethod"] == "POST"
    assert webhook["parameters"]["authentication"] == "none"
    for node in workflow["nodes"]:
        if node["type"] in ("n8n-nodes-base.httpRequest", "n8n-nodes-base.httpRequestTool"):
            assert node["parameters"]["url"].lstrip("=").startswith("http://workshop:8000/"), node["name"]
            assert "authentication" not in node["parameters"], node["name"]
        if node["type"] == "n8n-nodes-base.wait" and node["parameters"].get("resume") == "form":
            assert node["parameters"]["incomingAuthentication"] == "none"
    names = {node["name"] for node in workflow["nodes"]}
    assert set(workflow["connections"]) <= names
    assert {target["node"] for outputs in workflow["connections"].values() for kind in outputs.values() for links in kind for target in links} <= names


def test_ids_are_distinct_and_base_is_pinned():
    ids = [load(phase)["id"] for phase in workflows.PHASES]
    assert ids[0] == "romhackBase00001"  # compose.yml's n8n-import checks this id
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("phase", ["C1", "C2", "C3"])
def test_agent_waits_for_a_participant_model(phase):
    workflow = load(phase)
    agent = next(node for node in workflow["nodes"] if node["type"] == "@n8n/n8n-nodes-langchain.agent")
    assert agent["name"] == "King Kai - AI Agent" and agent["parameters"]["options"]["maxIterations"] == 10
    assert "index=romhack" in agent["parameters"]["options"]["systemMessage"]
    note = next(node for node in workflow["nodes"] if node["type"] == "n8n-nodes-base.stickyNote")
    assert "Chat Model" in note["parameters"]["content"] and "tool calling" in note["parameters"]["content"]
    feeding = {(source, kind) for source, outputs in workflow["connections"].items() for kind, links in outputs.items()
               for group in links for target in group if target["node"] == agent["name"]}
    assert {(tool, "ai_tool") for tool in TOOLS} | {("Structured verdict", "ai_outputParser")} <= feeding
    assert not any(kind == "ai_languageModel" for _, kind in feeding)


def test_readme_prints_the_solution_system_message():
    readme = (Path(__file__).parents[1] / "README.md").read_text()
    # The README indents the block by three spaces inside a numbered step.
    printed = "\n".join(line[3:] for line in readme.splitlines())
    assert workflows.SYSTEM_MESSAGE in printed
