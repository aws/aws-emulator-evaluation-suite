"""filter-multiple-action-filters-is-and-semantics."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-multiple-action-filters-is-and-semantics"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FEATURE EQUALS <f> and SEVERITY EQUALS <s> in one call return exactly the unfiltered actions
    matching both, and every returned action carries both values: action filters AND together."""

    bcm = ctx.client("bcm-recommended-actions")
    baseline = bcm.list_recommended_actions()["recommendedActions"]
    if not baseline:
        raise AssertionError(
            "account has zero recommended actions; there is no write API for this "
            "service so feature/severity values cannot be manufactured to filter on "
            "-- needs a sandbox account with at least one naturally-occurring action"
        )

    target = baseline[0]
    target_feature, target_severity = target["feature"], target["severity"]
    expected_ids = {
        a["id"]
        for a in baseline
        if a["feature"] == target_feature and a["severity"] == target_severity
    }

    combined = bcm.list_recommended_actions(
        filter={
            "actions": [
                {"key": "FEATURE", "matchOption": "EQUALS", "values": [target_feature]},
                {"key": "SEVERITY", "matchOption": "EQUALS", "values": [target_severity]},
            ]
        }
    )["recommendedActions"]
    combined_ids = {a["id"] for a in combined}

    assert combined_ids == expected_ids, (
        f"AND of FEATURE={target_feature!r}+SEVERITY={target_severity!r} returned "
        f"{combined_ids}, expected exactly {expected_ids} (computed from the unfiltered "
        f"baseline)"
    )
    for action in combined:
        assert action["feature"] == target_feature and action["severity"] == target_severity, (
            f"item {action.get('id')} in AND-filtered result has "
            f"feature={action.get('feature')!r} severity={action.get('severity')!r}, "
            f"expected feature={target_feature!r} severity={target_severity!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
