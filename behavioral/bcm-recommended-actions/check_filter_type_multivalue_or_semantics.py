"""filter-type-multivalue-or-semantics."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-type-multivalue-or-semantics"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]

_TARGET_TYPES = {"CREATE_BUDGET", "MIGRATE_TO_GRANULAR_PERMISSIONS"}


def _collect(client, **kwargs):
    items = []
    token = None
    for _ in range(500):
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = client.list_recommended_actions(**params)
        items.extend(resp.get("recommendedActions", []))
        token = resp.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError("pagination did not terminate within 500 pages")
    return items


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TYPE EQUALS [CREATE_BUDGET, MIGRATE_TO_GRANULAR_PERMISSIONS] returns only actions of either type
    and its NOT_EQUALS complement only the rest; the two sets are disjoint and union to the unfiltered
    listing: a values list is ORed."""
    client = ctx.client("bcm-recommended-actions")

    unfiltered = _collect(client)
    unfiltered_ids = {a["id"] for a in unfiltered}

    equals_filter = {
        "actions": [
            {"key": "TYPE", "matchOption": "EQUALS", "values": sorted(_TARGET_TYPES)}
        ]
    }
    not_equals_filter = {
        "actions": [
            {"key": "TYPE", "matchOption": "NOT_EQUALS", "values": sorted(_TARGET_TYPES)}
        ]
    }

    equals_items = _collect(client, filter=equals_filter)
    not_equals_items = _collect(client, filter=not_equals_filter)

    for action in equals_items:
        assert action["type"] in _TARGET_TYPES, action["type"]
    for action in not_equals_items:
        assert action["type"] not in _TARGET_TYPES, action["type"]

    equals_ids = {a["id"] for a in equals_items}
    not_equals_ids = {a["id"] for a in not_equals_items}

    assert equals_ids.isdisjoint(not_equals_ids), equals_ids & not_equals_ids
    assert (
        equals_ids | not_equals_ids == unfiltered_ids
    ), unfiltered_ids ^ (equals_ids | not_equals_ids)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
