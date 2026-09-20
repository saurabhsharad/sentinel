"""Mock Slack. Records posts to internal channels."""
from __future__ import annotations

from typing import Any, Dict, List


class Slack:
    def __init__(self):
        self.posts: List[Dict[str, Any]] = []

    def post(self, channel: str, text: Any) -> dict:
        rec = {"channel": channel, "text": text}
        self.posts.append(rec)
        return {"ok": True, "posted": rec}
