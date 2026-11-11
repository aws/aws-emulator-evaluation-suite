"""type-not-equals-unknown-value-returns-everything."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "type-not-equals-unknown-value-returns-everything"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]


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


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TYPE NOT_EQUALS a value outside the ActionType enum excludes nothing: the filtered listing holds
    exactly the ids of the unfiltered listing."""
    client = ctx.client("bcm-recommended-actions")
    bogus_type = "SIM2REAL_NOT_A_REAL_ACTION_TYPE_ABC"

    unfiltered = _collect(client)
    unfiltered_ids = {a["id"] for a in unfiltered}

    kept = _collect(
        client,
        filter={"actions": [{"key": "TYPE", "matchOption": "NOT_EQUALS", "values": [bogus_type]}]},
    )
    kept_ids = {a["id"] for a in kept}

    assert kept_ids == unfiltered_ids, (kept_ids, unfiltered_ids)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
