"""Small versioned key/value store: in memory for tests, SQLite in the container."""
import copy
import json
import sqlite3
import threading
from pathlib import Path
from typing import Callable

RECORD_LIMIT = 300_000


class Conflict(RuntimeError):
    pass


class MemoryStore:
    def __init__(self):
        self.items = {}
        self.lock = threading.RLock()

    def get(self, key):
        with self.lock:
            return copy.deepcopy(self.items.get(key))

    def put(self, key, value, version):
        with self.lock:
            if (self.items.get(key) or {}).get("version", 0) != version:
                raise Conflict(key)
            result = copy.deepcopy(value)
            result["version"] = version + 1
            if len(json.dumps(result).encode()) > RECORD_LIMIT:
                raise ValueError("Record exceeded workshop safety limit")
            self.items[key] = result
            return copy.deepcopy(result)

    def list(self, prefix):
        with self.lock:
            return [(key, copy.deepcopy(value)) for key, value in self.items.items() if key.startswith(prefix)]

    def delete(self, key):
        with self.lock:
            self.items.pop(key, None)

    def update(self, key, transform: Callable):
        """Read-modify-write with optimistic versioning; ``transform`` may raise to abort."""
        for _ in range(100):
            old = self.get(key)
            value = transform(copy.deepcopy(old))
            try:
                return self.put(key, value, (old or {}).get("version", 0))
            except Conflict:
                continue
        raise Conflict("Concurrent state changes; retry request")


class SQLiteStore(MemoryStore):
    """Same contract as MemoryStore, persisted so a container restart keeps state."""

    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA case_sensitive_like=ON")
        self.db.execute("CREATE TABLE IF NOT EXISTS records (key TEXT PRIMARY KEY, version INTEGER NOT NULL, payload TEXT NOT NULL)")

    def get(self, key):
        with self.lock:
            row = self.db.execute("SELECT payload FROM records WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key, value, version):
        value = copy.deepcopy(value)
        value["version"] = version + 1
        payload = json.dumps(value, separators=(",", ":"))
        if len(payload.encode()) > RECORD_LIMIT:
            raise ValueError("Record exceeded workshop safety limit")
        with self.lock:
            if version:
                changed = self.db.execute("UPDATE records SET version = ?, payload = ? WHERE key = ? AND version = ?", (version + 1, payload, key, version)).rowcount
            else:
                changed = self.db.execute("INSERT OR IGNORE INTO records (key, version, payload) VALUES (?, 1, ?)", (key, payload)).rowcount
        if not changed:
            raise Conflict(key)
        return value

    def list(self, prefix):
        escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with self.lock:
            rows = self.db.execute("SELECT key, payload FROM records WHERE key LIKE ? ESCAPE '\\'", (escaped + "%",)).fetchall()
        return [(key, json.loads(payload)) for key, payload in rows]

    def delete(self, key):
        with self.lock:
            self.db.execute("DELETE FROM records WHERE key = ?", (key,))
