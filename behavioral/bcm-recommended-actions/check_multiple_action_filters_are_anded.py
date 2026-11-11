"""multiple-action-filters-are-anded."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "multiple-action-filters-are-anded"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two ActionFilter entries in one filter (FEATURE EQUALS f, SEVERITY EQUALS s) are ANDed: the result
    is exactly the listed items matching both values, and a subset of the FEATURE-only result."""
    baseline_items = _list_all(ctx)
    if not baseline_items:
        raise AssertionError(
            "account has zero recommended actions; bcm-recommended-actions has no "
            "write API so a feature/severity combination cannot be manufactured to "
            "filter on -- needs a sandbox account with at least one naturally-occurring action"
        )

    target = baseline_items[0]
    target_feature, target_severity = target["feature"], target["severity"]
    expected_ids = {
        a["id"] for a in baseline_items if a["feature"] == target_feature and a["severity"] == target_severity
    }
    assert target["id"] in expected_ids, (target["id"], expected_ids)

    filter_feature_only = {"actions": [{"key": "FEATURE", "matchOption": "EQUALS", "values": [target_feature]}]}
    filter_anded = {
        "actions": [
            {"key": "FEATURE", "matchOption": "EQUALS", "values": [target_feature]},
            {"key": "SEVERITY", "matchOption": "EQUALS", "values": [target_severity]},
        ]
    }

    feature_only_items = _list_all(ctx, request_filter=filter_feature_only)
    anded_items = _list_all(ctx, request_filter=filter_anded)

    feature_only_ids = {a["id"] for a in feature_only_items}
    anded_ids = {a["id"] for a in anded_items}

    assert anded_ids == expected_ids, (anded_ids, expected_ids)
    assert all(
        a["feature"] == target_feature and a["severity"] == target_severity for a in anded_items
    ), anded_items
    assert anded_ids.issubset(feature_only_ids), (anded_ids, feature_only_ids)


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
