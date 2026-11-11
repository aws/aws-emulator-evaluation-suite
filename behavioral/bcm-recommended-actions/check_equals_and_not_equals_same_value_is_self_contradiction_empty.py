"""equals-and-not-equals-same-value-is-self-contradiction-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "equals-and-not-equals-same-value-is-self-contradiction-empty"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SEVERITY EQUALS [CRITICAL] ANDed with SEVERITY NOT_EQUALS [CRITICAL] in one request returns an
    empty recommendedActions list and no nextToken: no action satisfies a contradiction."""
    client = ctx.client("bcm-recommended-actions")

    resp = client.list_recommended_actions(
        filter={
            "actions": [
                {"key": "SEVERITY", "matchOption": "EQUALS", "values": ["CRITICAL"]},
                {"key": "SEVERITY", "matchOption": "NOT_EQUALS", "values": ["CRITICAL"]},
            ]
        }
    )
    assert resp["recommendedActions"] == [], (
        f"expected empty list for self-contradictory SEVERITY EQUALS/NOT_EQUALS "
        f"[CRITICAL], got {resp['recommendedActions']!r}"
    )
    assert not resp.get("nextToken"), (
        f"expected no nextToken on an empty page, got {resp.get('nextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
