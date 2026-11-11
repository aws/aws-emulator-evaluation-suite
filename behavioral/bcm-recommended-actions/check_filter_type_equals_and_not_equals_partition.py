"""filter-type-equals-and-not-equals-partition."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "filter-type-equals-and-not-equals-partition"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TYPE EQUALS <v> and TYPE NOT_EQUALS <v>, with <v> taken from a listed action, return disjoint sets
    whose union is exactly the unfiltered listing, each item obeying the filter it matched."""
    all_items = _list_all(ctx)
    if not all_items:
        raise AssertionError(
            "account has zero recommended actions; there is no write API for this "
            "service so a TYPE value cannot be manufactured to filter on -- needs a "
            "sandbox account with at least one naturally-occurring action"
        )
    target_type = all_items[0]["type"]

    filter_eq = {"actions": [{"key": "TYPE", "matchOption": "EQUALS", "values": [target_type]}]}
    filter_ne = {"actions": [{"key": "TYPE", "matchOption": "NOT_EQUALS", "values": [target_type]}]}

    eq_items = _list_all(ctx, request_filter=filter_eq)
    ne_items = _list_all(ctx, request_filter=filter_ne)

    all_ids = {a["id"] for a in all_items}
    eq_ids = {a["id"] for a in eq_items}
    ne_ids = {a["id"] for a in ne_items}

    assert eq_ids.isdisjoint(ne_ids), (
        f"EQUALS {target_type!r} and NOT_EQUALS {target_type!r} overlap on ids {eq_ids & ne_ids}"
    )
    assert eq_ids | ne_ids == all_ids, (
        f"EQUALS/NOT_EQUALS union {eq_ids | ne_ids} does not cover the unfiltered set {all_ids}"
    )
    assert all(a["type"] == target_type for a in eq_items), (
        f"EQUALS {target_type!r} returned items with a different type: "
        f"{[a['type'] for a in eq_items if a['type'] != target_type]}"
    )
    assert all(a["type"] != target_type for a in ne_items), (
        f"NOT_EQUALS {target_type!r} returned items with that type: "
        f"{[a['id'] for a in ne_items if a['type'] == target_type]}"
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
    else:
        raise AssertionError(f"pagination did not terminate within {max_pages} pages")
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
