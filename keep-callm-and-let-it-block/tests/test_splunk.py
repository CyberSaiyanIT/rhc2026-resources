import base64
import json
import threading
from urllib.parse import parse_qs

import httpx
import pytest

from romhack import splunk


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def form(request):
    return {key: values[0] for key, values in parse_qs(request.content.decode()).items()}


def basic(request):
    return base64.b64decode(request.headers["authorization"].removeprefix("Basic ")).decode()


def event(i, source="waf"):
    return {"source": source, "timestamp": 100.0 + i, "event_id": f"e{i}"}


# --- HEC -----------------------------------------------------------------------

def test_hec_flush_posts_buffered_batch(config):
    hec = splunk.Hec(config)
    hec([event(0), event(1, "web")])
    hec([event(2, "audit")])
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json={"text": "Success"})

    assert hec.flush(client(handle)) == 3
    [request] = seen
    assert str(request.url) == config["splunk_hec_url"] + "/services/collector/event"
    assert request.headers["authorization"] == "Splunk " + config["splunk_hec_token"]
    lines = [json.loads(line) for line in request.content.decode().splitlines()]
    assert [line["sourcetype"] for line in lines] == ["romhack:waf", "romhack:web", "romhack:audit"]
    assert {line["index"] for line in lines} == {"romhack"}
    assert lines[1]["time"] == 101.0 and lines[1]["event"] == event(1, "web")
    assert hec.flush(client(handle)) == 0 and len(seen) == 1


def test_hec_requeues_in_order_on_http_error(config):
    hec = splunk.Hec(config)
    hec([event(i) for i in range(3)])

    with pytest.raises(httpx.HTTPStatusError):
        hec.flush(client(lambda request: httpx.Response(503)))
    with pytest.raises(httpx.ConnectError):
        hec.flush(client(lambda request: (_ for _ in ()).throw(httpx.ConnectError("starting"))))
    hec([event(3)])

    seen = []
    hec.flush(client(lambda request: seen.append(request) or httpx.Response(200)))
    assert [json.loads(line)["event"]["event_id"] for line in seen[0].content.decode().splitlines()] == ["e0", "e1", "e2", "e3"]


def test_hec_batches_and_bounds_buffer(config):
    hec = splunk.Hec(config, limit=600)
    hec([event(i) for i in range(700)])
    batches = []
    ok = client(lambda request: batches.append([json.loads(line)["event"]["event_id"] for line in request.content.decode().splitlines()]) or httpx.Response(200))
    assert hec.flush(ok) == 500
    assert hec.flush(ok) == 100
    assert [len(batch) for batch in batches] == [500, 100]
    assert batches[0][0] == "e100" and batches[1][-1] == "e699"  # the oldest were dropped


def test_hec_run_stops(config):
    hec = splunk.Hec(config)
    stop = threading.Event()
    stop.set()
    hec.run(stop)


# --- search --------------------------------------------------------------------

def export(*items):
    return "\n".join(json.dumps(item) for item in items) + "\n\n"


def test_search_parses_export_rows(config):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, text=export(
            {"preview": True, "result": {"src_ip": "preview"}},
            {"preview": False, "result": {"src_ip": "198.51.100.10", "count": "16"}},
            {"result": {"src_ip": "198.51.100.20"}},
            {"preview": False, "lastrow": True},
            {"messages": [{"type": "INFO", "text": "fine"}]},
        ))

    rows = splunk.search(config, "index=romhack | stats count by src_ip", http=client(handle))
    assert rows == [{"src_ip": "198.51.100.10", "count": "16"}, {"src_ip": "198.51.100.20"}]
    [request] = seen
    assert str(request.url) == config["splunk_api_url"] + "/services/search/jobs/export"
    assert basic(request) == f"{config['splunk_analyst_user']}:{config['splunk_analyst_password']}"
    body = form(request)
    assert body["search"] == "search index=romhack | stats count by src_ip"
    assert (body["earliest_time"], body["latest_time"], body["output_mode"], body["count"]) == ("-15m", "now", "json", "100")


def test_search_limits_row_count(config):
    rows = [{"result": {"n": i}} for i in range(5)]
    assert splunk.search(config, "x", count=2, http=client(lambda request: httpx.Response(200, text=export(*rows)))) == [{"n": 0}, {"n": 1}]


@pytest.mark.parametrize("kind", ["ERROR", "FATAL"])
def test_search_raises_on_error_messages(config, kind):
    body = export({"messages": [{"type": kind, "text": "Unknown search command 'foo'."}]})
    with pytest.raises(RuntimeError, match="Unknown search command"):
        splunk.search(config, "| foo", http=client(lambda request: httpx.Response(200, text=body)))


def test_search_scopes_slims_and_stops_at_count(config):
    seen = []
    def handle(request):
        seen.append(form(request))
        return httpx.Response(200, text=export(*({"preview": False, "result": {"_time": "t", "_raw": json.dumps({"path": f"/{i}", "status": 404, "timestamp": 1}), "_bkt": "b", "splunk_server": "s", "date_hour": "1", "src_ip": "198.51.100.10"}} for i in range(5))))
    rows = splunk.search(config, "index=romhack src_ip=198.51.100.10", run_id="r1", count=3, http=client(handle))
    assert seen[0]["search"] == 'search run_id="r1" index=romhack src_ip=198.51.100.10'
    assert rows == [{"path": f"/{i}", "status": 404, "_time": "t", "src_ip": "198.51.100.10"} for i in range(3)]


@pytest.mark.parametrize("spl,expected", [
    ("index=romhack", 'search run_id="r" index=romhack'),
    ("search index=romhack | stats count", 'search run_id="r" index=romhack | stats count'),
    ("| tstats count where index=romhack", "| tstats count where index=romhack"),
])
def test_scope_limits_ordinary_searches_to_the_run(spl, expected):
    assert splunk.scope(spl, "r") == expected


def test_search_http_error_propagates(config):
    with pytest.raises(httpx.HTTPStatusError):
        splunk.search(config, "x", http=client(lambda request: httpx.Response(500)))


def test_vpn_evidence_ready(config):
    seen = []

    def answer(rows):
        def handle(request):
            seen.append(form(request))
            return httpx.Response(200, text=export(*({"result": row} for row in rows)))
        return client(handle)

    assert splunk.vpn_evidence_ready(config, "run-1", "198.51.100.40", http=answer([{"evidence_ready": "1"}])) is True
    assert splunk.vpn_evidence_ready(config, "run-1", "198.51.100.40", http=answer([])) is False
    assert 'run_id="run-1"' in seen[0]["search"] and 'src_ip="198.51.100.40"' in seen[0]["search"]
    assert seen[0]["earliest_time"] == "0"


# --- analyst user --------------------------------------------------------------

def test_ensure_analyst_existing_user(config):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json={"entry": []})

    assert splunk.ensure_analyst(config, http=client(handle)) is False
    [request] = seen
    assert request.method == "GET" and request.url.path == "/services/authentication/users/analyst"
    assert basic(request) == "admin:" + config["splunk_admin_password"]


def test_ensure_analyst_creates_missing_user(config):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(404 if request.method == "GET" else 201)

    assert splunk.ensure_analyst(config, http=client(handle)) is True
    create = seen[1]
    assert create.method == "POST" and create.url.path == "/services/authentication/users"
    assert form(create) == {"name": "analyst", "password": config["splunk_analyst_password"], "roles": "romhack_analyst", "output_mode": "json"}


@pytest.mark.parametrize("statuses", [(500,), (404, 400)])
def test_ensure_analyst_errors_propagate(config, statuses):
    answers = iter(statuses)
    with pytest.raises(httpx.HTTPStatusError):
        splunk.ensure_analyst(config, http=client(lambda request: httpx.Response(next(answers))))


def test_wait_until():
    stop = threading.Event()
    calls = []

    def predicate():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("not yet")
        return len(calls) >= 3

    assert splunk.wait_until(predicate, stop, interval=0) is True
    assert len(calls) == 3
    stop.set()
    assert splunk.wait_until(lambda: True, stop) is False


@pytest.mark.parametrize("spl,expected", [
    ("index=romhack", "search index=romhack"),
    ("  search index=romhack", "search index=romhack"),
    ("SEARCH index=romhack", "SEARCH index=romhack"),
    ("| tstats count where index=romhack", "| tstats count where index=romhack"),
])
def test_normalize_adds_implicit_search(spl, expected):
    assert splunk.normalize(spl) == expected
