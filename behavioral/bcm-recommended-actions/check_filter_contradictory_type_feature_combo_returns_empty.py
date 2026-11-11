"""filter-contradictory-type-feature-combo-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-contradictory-type-feature-combo-returns-empty"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TYPE EQUALS ADD_ALTERNATE_BILLING_CONTACT ANDed with FEATURE EQUALS IAM succeeds with an empty
    page and no nextToken: that type always carries feature ACCOUNT, so the combination matches nothing."""
    client = ctx.client("bcm-recommended-actions")
    request_filter = {
        "actions": [
            {"key": "TYPE", "matchOption": "EQUALS", "values": ["ADD_ALTERNATE_BILLING_CONTACT"]},
            {"key": "FEATURE", "matchOption": "EQUALS", "values": ["IAM"]},
        ]
    }
    resp = client.list_recommended_actions(filter=request_filter)
    assert resp["recommendedActions"] == [], (
        "self-contradictory TYPE=ADD_ALTERNATE_BILLING_CONTACT AND FEATURE=IAM filter "
        f"must return an empty page, got {resp['recommendedActions']!r}"
    )
    assert resp.get("nextToken") in (None, ""), (
        f"empty page must carry no continuation token, got nextToken={resp.get('nextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
