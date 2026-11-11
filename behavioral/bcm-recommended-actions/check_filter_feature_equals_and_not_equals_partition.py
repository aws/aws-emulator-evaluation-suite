"""filter-feature-equals-and-not-equals-partition."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "filter-feature-equals-and-not-equals-partition"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]

_FEATURE_VALUE = "IAM"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FEATURE EQUALS <v> and FEATURE NOT_EQUALS <v> return disjoint sets whose union is exactly the
    unfiltered listing, each item obeying the filter it matched."""
    filter_eq = {"actions": [{"key": "FEATURE", "matchOption": "EQUALS", "values": [_FEATURE_VALUE]}]}
    filter_ne = {"actions": [{"key": "FEATURE", "matchOption": "NOT_EQUALS", "values": [_FEATURE_VALUE]}]}

    all_items = _list_all(ctx)
    if not all_items:
        raise AssertionError(
            "account has zero recommended actions; there is no write API for this "
            "service so items cannot be manufactured -- the partition invariant is "
            "vacuously true over an empty set and needs a sandbox account with at "
            "least one action to mean anything"
        )

    eq_items = _list_all(ctx, request_filter=filter_eq)
    ne_items = _list_all(ctx, request_filter=filter_ne)

    all_ids = {a["id"] for a in all_items}
    eq_ids = {a["id"] for a in eq_items}
    ne_ids = {a["id"] for a in ne_items}

    assert eq_ids.isdisjoint(ne_ids), (eq_ids, ne_ids)
    assert eq_ids | ne_ids == all_ids, (eq_ids | ne_ids, all_ids)
    assert all(a["feature"] == _FEATURE_VALUE for a in eq_items), eq_items
    assert all(a["feature"] != _FEATURE_VALUE for a in ne_items), ne_items


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
