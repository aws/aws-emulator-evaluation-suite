"""feature-equals-unknown-value-returns-empty-not-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "feature-equals-unknown-value-returns-empty-not-error"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FEATURE EQUALS a well-formed feature string that is not a real feature succeeds with an empty
    recommendedActions list and no nextToken: filter values are not validated against the enum."""
    client = ctx.client("bcm-recommended-actions")
    bogus_feature = "SIM2REAL_NOT_A_REAL_FEATURE_XYZ"

    baseline = client.list_recommended_actions()["recommendedActions"]
    if not baseline:
        raise AssertionError(
            "account has zero recommended actions; there is no write API for this "
            "service so a positive control cannot be manufactured -- needs a sandbox "
            "account with at least one action, otherwise a target that ignores "
            "filtering entirely would also read as empty"
        )

    resp = client.list_recommended_actions(
        filter={"actions": [{"key": "FEATURE", "matchOption": "EQUALS", "values": [bogus_feature]}]}
    )
    assert resp["recommendedActions"] == [], (
        f"expected no matches for an unreal feature value, got {resp['recommendedActions']!r} "
        f"against a non-empty baseline of {len(baseline)} action(s)"
    )
    assert not resp.get("nextToken"), f"expected no nextToken on an empty page, got {resp.get('nextToken')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
