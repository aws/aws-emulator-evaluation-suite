"""filter-type-partition-invariant."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-type-partition-invariant"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]

_TARGET_TYPE = "CREATE_BUDGET"


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
    """TYPE EQUALS/NOT_EQUALS on the same value exactly partition the unfiltered result set."""
    client = ctx.client("bcm-recommended-actions")

    unfiltered = _collect(client)
    unfiltered_ids = {a["id"] for a in unfiltered}
    assert unfiltered_ids, "expected at least one recommended action in this account (none returned unfiltered)"

    equals_filter = {"actions": [{"key": "TYPE", "matchOption": "EQUALS", "values": [_TARGET_TYPE]}]}
    not_equals_filter = {
        "actions": [{"key": "TYPE", "matchOption": "NOT_EQUALS", "values": [_TARGET_TYPE]}]
    }

    equals_items = _collect(client, filter=equals_filter)
    not_equals_items = _collect(client, filter=not_equals_filter)

    for action in equals_items:
        assert action.get("type") == _TARGET_TYPE, (
            f"TYPE EQUALS {_TARGET_TYPE} returned {action.get('type')!r} for id={action.get('id')!r}"
        )
    for action in not_equals_items:
        assert action.get("type") != _TARGET_TYPE, (
            f"TYPE NOT_EQUALS {_TARGET_TYPE} returned an excluded value for id={action.get('id')!r}"
        )

    equals_ids = {a["id"] for a in equals_items}
    not_equals_ids = {a["id"] for a in not_equals_items}

    assert equals_ids, f"TYPE EQUALS {_TARGET_TYPE} returned no items; unfiltered set had {len(unfiltered_ids)}"
    assert not_equals_ids, (
        f"TYPE NOT_EQUALS {_TARGET_TYPE} returned no items; unfiltered set had {len(unfiltered_ids)}"
    )
    assert equals_ids.isdisjoint(not_equals_ids), (
        f"EQUALS and NOT_EQUALS partitions overlap: {equals_ids & not_equals_ids}"
    )
    assert equals_ids | not_equals_ids == unfiltered_ids, (
        "EQUALS union NOT_EQUALS does not reconstruct the unfiltered set: "
        f"missing={unfiltered_ids - (equals_ids | not_equals_ids)} "
        f"extra={(equals_ids | not_equals_ids) - unfiltered_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
