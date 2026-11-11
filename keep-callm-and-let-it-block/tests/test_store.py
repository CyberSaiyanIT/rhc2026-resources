import pytest

from romhack.store import RECORD_LIMIT, Conflict, MemoryStore, SQLiteStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return MemoryStore() if request.param == "memory" else SQLiteStore(tmp_path / "db" / "workshop.db")


def test_missing_key_reads_as_none(store):
    assert store.get("nope") is None


def test_put_creates_then_bumps_version(store):
    first = store.put("k", {"a": 1}, 0)
    assert first == {"a": 1, "version": 1}
    assert store.get("k") == {"a": 1, "version": 1}
    second = store.put("k", {"a": 2}, 1)
    assert second["version"] == 2
    assert store.get("k") == {"a": 2, "version": 2}


@pytest.mark.parametrize("version", [0, 2])
def test_put_with_stale_version_conflicts(store, version):
    store.put("k", {"a": 1}, 0)
    with pytest.raises(Conflict):
        store.put("k", {"a": 2}, version)
    assert store.get("k") == {"a": 1, "version": 1}


def test_put_on_missing_key_with_nonzero_version_conflicts(store):
    with pytest.raises(Conflict):
        store.put("k", {"a": 1}, 3)
    assert store.get("k") is None


def test_returned_values_are_copies(store):
    store.put("k", {"items": [1]}, 0)
    value = store.get("k")
    value["items"].append(2)
    assert store.get("k")["items"] == [1]


def test_list_by_prefix(store):
    for key in ("alert#1", "alert#2", "approval#1", "lab"):
        store.put(key, {"key": key}, 0)
    assert sorted(key for key, _ in store.list("alert#")) == ["alert#1", "alert#2"]
    assert dict(store.list("approval#"))["approval#1"]["key"] == "approval#1"
    assert store.list("missing#") == []


@pytest.mark.parametrize("prefix,expected", [
    ("a_b", ["a_b#1"]),
    ("a%c", ["a%c#1"]),
    ("a\\d", ["a\\d#1"]),
])
def test_list_treats_like_wildcards_literally(store, prefix, expected):
    for key in ("a_b#1", "axb#1", "a%c#1", "abbc#1", "a\\d#1", "ad#1"):
        store.put(key, {}, 0)
    assert sorted(key for key, _ in store.list(prefix)) == expected


def test_delete(store):
    store.put("k", {}, 0)
    store.delete("k")
    store.delete("k")
    assert store.get("k") is None
    assert store.put("k", {}, 0)["version"] == 1


def test_record_size_limit(store):
    with pytest.raises(ValueError):
        store.put("big", {"blob": "x" * RECORD_LIMIT}, 0)
    assert store.get("big") is None


def test_update_creates_and_transforms(store):
    assert store.update("counter", lambda old: {"n": (old or {"n": 0})["n"] + 1}) == {"n": 1, "version": 1}
    assert store.update("counter", lambda old: {"n": old["n"] + 1}) == {"n": 2, "version": 2}


def test_update_abort_leaves_value_unchanged(store):
    store.put("k", {"n": 1}, 0)

    def refuse(old):
        raise RuntimeError("abort")

    with pytest.raises(RuntimeError):
        store.update("k", refuse)
    assert store.get("k") == {"n": 1, "version": 1}


def test_update_retries_after_concurrent_write(store):
    store.put("k", {"n": 0}, 0)
    calls = []

    def transform(old):
        calls.append(old["n"])
        if len(calls) == 1:
            # Another writer wins the race between our read and our write.
            store.put("k", {"n": 10}, old["version"])
        return {"n": old["n"] + 1}

    assert store.update("k", transform)["n"] == 11
    assert calls == [0, 10]


def test_update_gives_up_after_persistent_conflicts(store):
    store.put("k", {"n": 0}, 0)
    calls = []

    def always_lose(old):
        calls.append(1)
        store.put("k", {"n": old["n"]}, old["version"])
        return old

    with pytest.raises(Conflict):
        store.update("k", always_lose)
    assert len(calls) == 100


def test_sqlite_persists_across_instances(tmp_path):
    path = tmp_path / "workshop.db"
    SQLiteStore(path).put("lab", {"run_id": "r1"}, 0)
    reopened = SQLiteStore(path)
    assert reopened.get("lab") == {"run_id": "r1", "version": 1}
    with pytest.raises(Conflict):
        reopened.put("lab", {"run_id": "r2"}, 0)
    assert reopened.put("lab", {"run_id": "r2"}, 1)["version"] == 2


def test_sqlite_list_prefix_is_case_sensitive_like_memory(tmp_path):
    store = SQLiteStore(tmp_path / "workshop.db")
    store.put("alert#1", {}, 0)
    assert store.list("ALERT#") == []
