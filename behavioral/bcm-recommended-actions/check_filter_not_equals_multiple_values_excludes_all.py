"""filter-not-equals-multiple-values-excludes-all."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "filter-not-equals-multiple-values-excludes-all"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]

_VALUES = ["IAM", "BUDGETS"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FEATURE EQUALS [IAM, BUDGETS] returns only actions with either feature and NOT_EQUALS the same
    list returns only actions with neither; the two sets are disjoint and union to the unfiltered listing."""
    filter_eq_either = {"actions": [{"key": "FEATURE", "matchOption": "EQUALS", "values": _VALUES}]}
    filter_ne_both = {"actions": [{"key": "FEATURE", "matchOption": "NOT_EQUALS", "values": _VALUES}]}

    all_items = _list_all(ctx)
    eq_items = _list_all(ctx, request_filter=filter_eq_either)
    ne_items = _list_all(ctx, request_filter=filter_ne_both)

    all_ids = {a["id"] for a in all_items}
    eq_ids = {a["id"] for a in eq_items}
    ne_ids = {a["id"] for a in ne_items}

    assert eq_ids.isdisjoint(ne_ids), (
        f"EQUALS{_VALUES} and NOT_EQUALS{_VALUES} overlap on ids {eq_ids & ne_ids}"
    )
    assert eq_ids | ne_ids == all_ids, (
        f"EQUALS{_VALUES} union NOT_EQUALS{_VALUES} = {eq_ids | ne_ids} but the unfiltered "
        f"listing has ids {all_ids}"
    )
    assert all(a["feature"] in _VALUES for a in eq_items), (
        f"EQUALS{_VALUES} returned a feature outside {_VALUES}: "
        f"{[a['feature'] for a in eq_items if a['feature'] not in _VALUES]}"
    )
    assert all(a["feature"] not in _VALUES for a in ne_items), (
        f"NOT_EQUALS{_VALUES} returned a feature inside {_VALUES}: "
        f"{[a['feature'] for a in ne_items if a['feature'] in _VALUES]}"
    )


def _list_all(ctx, request_filter: dict | None = None, max_pages: int = 200) -> list[dict[str, Any]]:
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
