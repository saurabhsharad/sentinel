"""Deterministic mock enterprise database (SQLite, in-memory).

All data is FAKE and generated deterministically from a fixed seed so the demo is
reproducible. Contains customers, test_customers, orders, and an archive_log.
"""
from __future__ import annotations

import random
import sqlite3
from typing import List

_FIRST = ["Ava", "Liam", "Mia", "Noah", "Emma", "Ethan", "Zoe", "Kai", "Ivy", "Leo"]
_LAST = ["Stone", "Vale", "Marsh", "Pike", "Reed", "Frost", "Lane", "Cross", "Hart", "Fox"]


def _make_customers(n: int, start_id: int, seed: int):
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        cid = start_id + i
        fn = rng.choice(_FIRST)
        ln = rng.choice(_LAST)
        email = f"{fn.lower()}.{ln.lower()}{cid}@example.com"
        phone = f"+1-555-{rng.randint(100, 999)}-{rng.randint(1000, 9999)}"
        rows.append((cid, f"{fn} {ln}", email, phone, f"2026-Q{rng.randint(1, 2)}"))
    return rows


class World:
    """Owns the SQLite connection. Tools go through this; the agent never does."""

    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self._build()

    def _build(self):
        c = self.conn.cursor()
        for t in ("customers", "test_customers"):
            c.execute(
                f"CREATE TABLE {t} (id INTEGER PRIMARY KEY, name TEXT, email TEXT, "
                f"phone TEXT, quarter TEXT, archived INTEGER DEFAULT 0)"
            )
        c.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, amount REAL)")
        c.execute("CREATE TABLE archive_log (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                  "table_name TEXT, record_count INTEGER, ts TEXT)")
        c.executemany("INSERT INTO customers VALUES (?,?,?,?,?,0)", _make_customers(200, 1, 42))
        c.executemany("INSERT INTO test_customers VALUES (?,?,?,?,?,0)", _make_customers(60, 9001, 7))
        rng = random.Random(99)
        orders = [(i, rng.randint(1, 200), round(rng.uniform(10, 500), 2)) for i in range(1, 501)]
        c.executemany("INSERT INTO orders VALUES (?,?,?)", orders)
        self.conn.commit()

    # --- read ---
    def read(self, table: str, columns: List[str], where_last_quarter: bool = False) -> List[dict]:
        have = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
        cols_list = [c for c in columns if c in have] or ["id"]
        cols = ",".join(cols_list)
        q = f"SELECT {cols} FROM {table}"
        if where_last_quarter:
            q += " WHERE quarter='2026-Q2'"
        return [dict(r) for r in self.conn.execute(q).fetchall()]

    def count(self, table: str, where_last_quarter: bool = False) -> int:
        q = f"SELECT COUNT(*) n FROM {table}"
        if where_last_quarter:
            q += " WHERE quarter='2026-Q2'"
        return self.conn.execute(q).fetchone()["n"]

    # --- reversible archive (soft delete) ---
    def soft_delete(self, table: str, where_last_quarter: bool = True) -> int:
        q = f"UPDATE {table} SET archived=1"
        if where_last_quarter:
            q += " WHERE quarter='2026-Q2'"
        cur = self.conn.execute(q)
        n = cur.rowcount
        self.conn.execute(
            "INSERT INTO archive_log (table_name, record_count, ts) VALUES (?,?,?)",
            (table, n, "2026-09-17T00:00:00Z"),
        )
        self.conn.commit()
        return n

    def hard_delete(self, table: str) -> int:  # exists but never granted
        cur = self.conn.execute(f"DELETE FROM {table}")
        self.conn.commit()
        return cur.rowcount
