"""filter-severity-partition-invariant."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-severity-partition-invariant"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]


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
    """SEVERITY EQUALS/NOT_EQUALS on the same value exactly partition the unfiltered result set."""
    client = ctx.client("bcm-recommended-actions")

    unfiltered = _collect(client)
    unfiltered_ids = {a["id"] for a in unfiltered}

    equals_filter = {"actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": ["CRITICAL"]}]}
    not_equals_filter = {"actions": [{"key": "SEVERITY", "matchOption": "NOT_EQUALS", "values": ["CRITICAL"]}]}

    equals_items = _collect(client, filter=equals_filter)
    not_equals_items = _collect(client, filter=not_equals_filter)

    for action in equals_items:
        severity = action.get("severity")
        assert severity == "CRITICAL", f"EQUALS CRITICAL returned severity={severity!r} for id={action.get('id')!r}"
    for action in not_equals_items:
        severity = action.get("severity")
        assert severity != "CRITICAL", f"NOT_EQUALS CRITICAL returned severity={severity!r} for id={action.get('id')!r}"

    equals_ids = {a["id"] for a in equals_items}
    not_equals_ids = {a["id"] for a in not_equals_items}

    overlap = equals_ids & not_equals_ids
    assert not overlap, f"EQUALS and NOT_EQUALS partitions overlap on ids={overlap!r}"
    missing = unfiltered_ids - (equals_ids | not_equals_ids)
    extra = (equals_ids | not_equals_ids) - unfiltered_ids
    assert not missing and not extra, (
        f"partition union does not reconstruct unfiltered set: missing={missing!r} extra={extra!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
