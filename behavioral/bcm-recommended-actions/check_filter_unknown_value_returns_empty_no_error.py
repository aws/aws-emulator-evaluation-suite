"""filter-unknown-value-returns-empty-no-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-unknown-value-returns-empty-no-error"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]

_BOGUS_TYPE = "THIS_TYPE_DOES_NOT_EXIST_XYZ"


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
    """TYPE EQUALS a value that is no enum member succeeds with an empty page and no nextToken, and
    over the full listing EQUALS it contributes nothing while NOT_EQUALS it returns exactly the
    unfiltered set: an unknown value matches nothing and is not rejected."""
    client = ctx.client("bcm-recommended-actions")

    unfiltered_ids = {a["id"] for a in _collect(client)}

    equals_filter = {"actions": [{"key": "TYPE", "matchOption": "EQUALS", "values": [_BOGUS_TYPE]}]}
    not_equals_filter = {
        "actions": [{"key": "TYPE", "matchOption": "NOT_EQUALS", "values": [_BOGUS_TYPE]}]
    }

    first_page = client.list_recommended_actions(filter=equals_filter)
    assert first_page["recommendedActions"] == [], (
        f"expected no matches for unmodeled TYPE {_BOGUS_TYPE!r}, got "
        f"{first_page['recommendedActions']!r}"
    )
    assert not first_page.get("nextToken"), (
        f"expected no nextToken on an empty page, got {first_page.get('nextToken')!r}"
    )

    equals_ids = {a["id"] for a in _collect(client, filter=equals_filter)}
    not_equals_ids = {a["id"] for a in _collect(client, filter=not_equals_filter)}

    assert equals_ids == set(), f"EQUALS on unmodeled value must contribute nothing, got {equals_ids!r}"
    assert not_equals_ids == unfiltered_ids, (
        f"NOT_EQUALS on a value no action can ever carry must equal the unfiltered set: "
        f"expected {unfiltered_ids!r}, got {not_equals_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
