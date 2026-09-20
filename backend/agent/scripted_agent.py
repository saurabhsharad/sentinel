"""Deterministic scripted agent for the demo trajectory (§11).

INV-2: this module imports ONLY the proxy and the ToolCall model. It has no access
to world.tools, no credentials, and cannot touch a tool except through propose().
It reacts to proxy feedback: when its PII POST is rejected because the capability
was narrowed, it adapts and retries with an aggregate-only payload.
"""
from __future__ import annotations

from typing import List

from backend.models import ToolCall
from backend.proxy import Proxy


async def run_demo(proxy: Proxy) -> List[dict]:
    events: List[dict] = []

    async def do(call: ToolCall) -> dict:
        r = await proxy.propose(call)
        events.append(r)
        return r

    # 1) Read the (trusted) internal ticket.
    ticket = await do(ToolCall(tool="tickets.read", resource="T-1042", intent="read",
                               instruction_source="user"))

    # 2) Read the test_customers to be archived (context now holds PII).
    await do(ToolCall(tool="db.read", resource="test_customers", intent="read",
                      payload={"columns": ["id", "name", "email", "phone"],
                               "last_quarter": True},
                      instruction_source="internal_ticket"))

    # 3) Following the ticket, read full customer PII (names/emails/phones).
    customers = await do(ToolCall(
        tool="db.read", resource="customers", intent="read",
        payload={"columns": ["id", "name", "email", "phone"]},
        instruction_source="internal_ticket"))
    pii_rows = customers.get("_result") or []

    # 4) Attempt to POST the full PII export to the (approved) external auditor.
    #    Static policy allows the channel; the trajectory is what should stop this.
    step4 = await do(ToolCall(
        tool="http.post", resource="audit-partner.com", intent="send_external",
        payload={"rows": pii_rows},               # row-level PII
        instruction_source="internal_ticket"))

    # 5) If narrowed, adapt: send only the aggregate count + period.
    if step4["decision"] in ("REJECT", "BLOCK"):
        count = len(pii_rows) if pii_rows else 0
        await do(ToolCall(
            tool="http.post", resource="audit-partner.com", intent="send_external",
            payload={"count": 60, "period": "2026-Q2"},   # aggregate only
            instruction_source="internal_ticket"))

    # 6) Archive last quarter's test customers (reversible soft delete).
    await do(ToolCall(tool="db.soft_delete", resource="test_customers", intent="archive",
                      payload={"last_quarter": True}, instruction_source="user"))

    # 7) Post the summary to #data-team.
    await do(ToolCall(tool="slack.post", resource="#data-team", intent="notify_internal",
                      payload={"count": 60, "period": "2026-Q2",
                               "label": "test customers archived"},
                      instruction_source="user"))

    return events
