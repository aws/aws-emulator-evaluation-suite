"""filter-feature-multivalue-or-semantics."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-feature-multivalue-or-semantics"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]

_TARGET_FEATURES = {"IAM", "BUDGETS"}


def _collect(client, **kwargs):
    items = []
    token = None
    for _ in range(200):
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = client.list_recommended_actions(**params)
        items.extend(resp.get("recommendedActions", []))
        token = resp.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError("pagination did not terminate within 200 pages")
    return items


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A filter with multiple values ORs them: EQUALS[IAM,BUDGETS] / NOT_EQUALS[IAM,BUDGETS] partition the listing."""
    client = ctx.client("bcm-recommended-actions")

    unfiltered = _collect(client)
    unfiltered_ids = {a["id"] for a in unfiltered}

    equals_filter = {
        "actions": [{"key": "FEATURE", "matchOption": "EQUALS", "values": ["IAM", "BUDGETS"]}]
    }
    not_equals_filter = {
        "actions": [{"key": "FEATURE", "matchOption": "NOT_EQUALS", "values": ["IAM", "BUDGETS"]}]
    }

    equals_items = _collect(client, filter=equals_filter)
    not_equals_items = _collect(client, filter=not_equals_filter)

    for action in equals_items:
        assert action["feature"] in _TARGET_FEATURES, (
            f"EQUALS[IAM,BUDGETS] returned {action['id']} with feature="
            f"{action['feature']!r}, expected one of {_TARGET_FEATURES}"
        )
    for action in not_equals_items:
        assert action["feature"] not in _TARGET_FEATURES, (
            f"NOT_EQUALS[IAM,BUDGETS] returned {action['id']} with feature="
            f"{action['feature']!r}, expected none of {_TARGET_FEATURES}"
        )

    equals_ids = {a["id"] for a in equals_items}
    not_equals_ids = {a["id"] for a in not_equals_items}

    assert equals_ids.isdisjoint(not_equals_ids), (
        f"EQUALS and NOT_EQUALS overlap: {equals_ids & not_equals_ids}"
    )
    assert equals_ids | not_equals_ids == unfiltered_ids, (
        f"EQUALS|NOT_EQUALS={equals_ids | not_equals_ids} does not reconstruct "
        f"the unfiltered listing {unfiltered_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
