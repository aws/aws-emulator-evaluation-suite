"""filter-severity-equals-and-not-equals-partition."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "filter-severity-equals-and-not-equals-partition"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]

_SEVERITY_VALUE = "CRITICAL"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Filtering on SEVERITY EQUALS <v> and SEVERITY NOT_EQUALS <v> partitions
    the full, unfiltered result set: disjoint subsets whose union is exactly
    the full set, each obeying the filter it matched."""
    filter_eq = {"actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": [_SEVERITY_VALUE]}]}
    filter_ne = {"actions": [{"key": "SEVERITY", "matchOption": "NOT_EQUALS", "values": [_SEVERITY_VALUE]}]}

    all_items = _list_all(ctx)
    eq_items = _list_all(ctx, request_filter=filter_eq)
    ne_items = _list_all(ctx, request_filter=filter_ne)

    all_ids = {a["id"] for a in all_items}
    eq_ids = {a["id"] for a in eq_items}
    ne_ids = {a["id"] for a in ne_items}

    overlap = eq_ids & ne_ids
    assert not overlap, f"EQUALS and NOT_EQUALS sets must be disjoint, but shared ids {overlap}"
    assert eq_ids | ne_ids == all_ids, (
        f"EQUALS union NOT_EQUALS must equal the unfiltered set: "
        f"missing={all_ids - (eq_ids | ne_ids)}, extra={(eq_ids | ne_ids) - all_ids}"
    )
    wrong_eq = [a["id"] for a in eq_items if a["severity"] != _SEVERITY_VALUE]
    assert not wrong_eq, f"EQUALS {_SEVERITY_VALUE} returned non-matching severities for ids {wrong_eq}"
    wrong_ne = [a["id"] for a in ne_items if a["severity"] == _SEVERITY_VALUE]
    assert not wrong_ne, f"NOT_EQUALS {_SEVERITY_VALUE} returned matching severities for ids {wrong_ne}"


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
