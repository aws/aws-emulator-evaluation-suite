"""empty-filter-actions-equivalent-to-no-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "empty-filter-actions-equivalent-to-no-filter"
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


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Passing filter={"actions": []} matches everything, exactly like omitting filter entirely."""
    client = ctx.client("bcm-recommended-actions")

    no_filter_ids = {a["id"] for a in _collect(client)}
    empty_actions_ids = {a["id"] for a in _collect(client, filter={"actions": []})}

    assert empty_actions_ids == no_filter_ids, (
        f"filter={{'actions': []}} returned {len(empty_actions_ids)} id(s) "
        f"({sorted(empty_actions_ids)[:5]}...), expected the same id set as "
        f"omitting filter entirely: {len(no_filter_ids)} id(s) "
        f"({sorted(no_filter_ids)[:5]}...); symmetric diff="
        f"{sorted(empty_actions_ids ^ no_filter_ids)[:5]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
