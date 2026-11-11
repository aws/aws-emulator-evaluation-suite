"""filter-severity-not-equals-all-values-returns-empty."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "filter-severity-not-equals-all-values-returns-empty"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]

_ALL_SEVERITIES = ["INFO", "WARNING", "CRITICAL"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SEVERITY NOT_EQUALS [INFO, WARNING, CRITICAL] succeeds with an empty page and no nextToken, while
    SEVERITY EQUALS the same three values returns exactly the unfiltered listing."""
    ne_filter = {
        "actions": [
            {"key": "SEVERITY", "matchOption": "NOT_EQUALS", "values": _ALL_SEVERITIES},
        ]
    }
    eq_filter = {
        "actions": [
            {"key": "SEVERITY", "matchOption": "EQUALS", "values": _ALL_SEVERITIES},
        ]
    }

    client = ctx.client("bcm-recommended-actions")
    ne_resp = client.list_recommended_actions(filter=ne_filter)
    assert ne_resp["recommendedActions"] == [], (
        f"NOT_EQUALS over the full severity enum must return no actions, got {ne_resp['recommendedActions']}"
    )
    assert ne_resp.get("nextToken") in (None, ""), (
        f"an empty, exhausted page must carry no nextToken, got {ne_resp.get('nextToken')!r}"
    )

    unfiltered = _list_all(ctx)
    eq_items = _list_all(ctx, request_filter=eq_filter)

    unfiltered_ids = {a["id"] for a in unfiltered}
    eq_ids = {a["id"] for a in eq_items}
    assert eq_ids == unfiltered_ids, (
        f"EQUALS over the full severity enum must recover the unfiltered listing exactly: "
        f"missing={unfiltered_ids - eq_ids} extra={eq_ids - unfiltered_ids}"
    )


def _list_all(ctx, request_filter: dict | None = None, max_pages: int = 50) -> list[dict[str, Any]]:
    client = ctx.client("bcm-recommended-actions")
    items: list[dict[str, Any]] = []
    next_token = None
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {}
        if request_filter is not None:
            kwargs["filter"] = request_filter
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_recommended_actions(**kwargs)
        items.extend(resp.get("recommendedActions", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
