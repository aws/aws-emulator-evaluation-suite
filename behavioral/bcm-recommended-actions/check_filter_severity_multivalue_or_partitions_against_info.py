"""filter-severity-multivalue-or-partitions-against-info."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-severity-multivalue-or-partitions-against-info"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]

_TARGET_SEVERITIES = {"WARNING", "CRITICAL"}
# CRITICAL and WARNING are listed before INFO deliberately: an account's population is often
# INFO-only, so a filter bug that only honors values[0] (or ANDs the list) would otherwise hide
# behind the coincidence of INFO being both present and last.
_ALL_SEVERITIES = ["CRITICAL", "WARNING", "INFO"]


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
    """SEVERITY EQUALS [CRITICAL, WARNING] and its NOT_EQUALS complement partition the unfiltered listing,
    each item obeying its filter, and EQUALS on all three severities returns the full listing while
    NOT_EQUALS on all three returns nothing: a values list is ORed."""
    client = ctx.client("bcm-recommended-actions")

    unfiltered = _collect(client)
    unfiltered_ids = {a["id"] for a in unfiltered}

    equals_filter = {
        "actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": ["WARNING", "CRITICAL"]}]
    }
    not_equals_filter = {
        "actions": [
            {"key": "SEVERITY", "matchOption": "NOT_EQUALS", "values": ["WARNING", "CRITICAL"]}
        ]
    }

    equals_items = _collect(client, filter=equals_filter)
    not_equals_items = _collect(client, filter=not_equals_filter)

    for action in equals_items:
        assert action["severity"] in _TARGET_SEVERITIES, (
            f"EQUALS[WARNING,CRITICAL] returned severity={action['severity']!r}, id={action['id']!r}"
        )
    for action in not_equals_items:
        assert action["severity"] not in _TARGET_SEVERITIES, (
            f"NOT_EQUALS[WARNING,CRITICAL] returned severity={action['severity']!r}, id={action['id']!r}"
        )

    equals_ids = {a["id"] for a in equals_items}
    not_equals_ids = {a["id"] for a in not_equals_items}

    assert equals_ids.isdisjoint(not_equals_ids), (
        f"EQUALS and NOT_EQUALS partitions overlap on ids {equals_ids & not_equals_ids}"
    )
    assert equals_ids | not_equals_ids == unfiltered_ids, (
        f"EQUALS|NOT_EQUALS union {equals_ids | not_equals_ids} != unfiltered {unfiltered_ids}"
    )

    # The account may hold no WARNING/CRITICAL action at all, which would let a target that ANDs
    # a multivalue filter, or only honors values[0], pass the assertions above by coincidence.
    # Naming every modeled severity value pins the OR/AND distinction to the closed enum.
    all_values_filter = {"actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": _ALL_SEVERITIES}]}
    none_values_filter = {
        "actions": [{"key": "SEVERITY", "matchOption": "NOT_EQUALS", "values": _ALL_SEVERITIES}]
    }
    all_values_ids = {a["id"] for a in _collect(client, filter=all_values_filter)}
    none_values_items = _collect(client, filter=none_values_filter)

    assert all_values_ids == unfiltered_ids, (
        f"EQUALS naming every modeled severity value must OR to the full listing: "
        f"got {all_values_ids}, expected {unfiltered_ids}"
    )
    assert not none_values_items, (
        f"NOT_EQUALS naming every modeled severity value must exclude everything, got "
        f"{[a['id'] for a in none_values_items]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
