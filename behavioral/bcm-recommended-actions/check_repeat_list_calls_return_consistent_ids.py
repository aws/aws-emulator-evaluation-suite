"""repeat-list-calls-return-consistent-ids."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "repeat-list-calls-return-consistent-ids"
GROUP = "consistency"
SERVICES = ["bcm-recommended-actions"]


def _collect(client, **kwargs):
    items = []
    token = None
    for _ in range(200):
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = client.list_recommended_actions(**params)
        items.extend(resp["recommendedActions"])
        token = resp.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError("pagination did not terminate within 200 pages")
    return items


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two back-to-back full listings (no mutation in between) return the same set of action ids."""
    client = ctx.client("bcm-recommended-actions")

    first_ids = {a["id"] for a in _collect(client)}
    second_ids = {a["id"] for a in _collect(client)}

    assert first_ids, (
        "this account reported zero recommended actions on the first listing; "
        "a target that always returns an empty list would pass this check vacuously"
    )
    assert first_ids == second_ids, (
        f"two back-to-back full listings disagreed: "
        f"only_in_first={first_ids - second_ids} only_in_second={second_ids - first_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
