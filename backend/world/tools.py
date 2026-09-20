"""Tool registry. The enforcement proxy owns this; the AGENT MUST NOT import it
(INV-2). Tools hold the real "credentials"/handles to the world."""
from __future__ import annotations

from typing import Any

from backend.world.db import World
from backend.world.http_sink import ExternalSink
from backend.world.slack import Slack
from backend.world.tickets import Tickets


class ToolRegistry:
    """Owns all world handles. Only the proxy dispatches through here."""

    def __init__(self):
        self.world = World()
        self.tickets = Tickets()
        self.slack = Slack()
        self.sink = ExternalSink()

    def dispatch(self, tool: str, resource: str, payload: Any) -> Any:
        if tool == "tickets.read":
            return self.tickets.read(resource)
        if tool == "db.read":
            cols = payload.get("columns", ["id"]) if isinstance(payload, dict) else ["id"]
            last_q = payload.get("last_quarter", False) if isinstance(payload, dict) else False
            return self.world.read(resource, cols, where_last_quarter=last_q)
        if tool == "db.soft_delete":
            return {"archived": self.world.soft_delete(resource)}
        if tool == "db.hard_delete":
            return {"deleted": self.world.hard_delete(resource)}
        if tool == "http.post":
            return self.sink.post(resource, payload)
        if tool == "slack.post":
            return self.slack.post(resource, payload)
        raise ValueError(f"unknown tool {tool}")
