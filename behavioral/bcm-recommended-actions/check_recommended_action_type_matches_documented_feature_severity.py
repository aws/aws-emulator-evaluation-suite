"""recommended-action-type-matches-documented-feature-severity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "recommended-action-type-matches-documented-feature-severity"
GROUP = "contract"
SERVICES = ["bcm-recommended-actions"]

# Fixed (type -> (feature, severity)) mapping per the AWS documentation table
# "Understanding recommended action types"
# (https://docs.aws.amazon.com/cost-management/latest/userguide/recommended-action-types.html).
# Every RecommendedAction whose `type` appears here MUST carry exactly this
# feature/severity pair -- the pairing is fixed by the service, not derived
# from account data, so the assertion holds regardless of which action types
# a given account happens to have.
_TYPE_TO_FEATURE_SEVERITY = {
    "PAYMENTS_PAST_DUE": ("PAYMENTS", "CRITICAL"),
    "UPDATE_INVALID_PAYMENT_METHOD": ("PAYMENTS", "CRITICAL"),
    "UPDATE_EXPIRED_PAYMENT_METHOD": ("PAYMENTS", "CRITICAL"),
    "UPDATE_TAX_REGISTRATION_NUMBER": ("TAX_SETTINGS", "WARNING"),
    "UPDATE_TAX_EXEMPTION_CERTIFICATE": ("TAX_SETTINGS", "WARNING"),
    "MIGRATE_TO_GRANULAR_PERMISSIONS": ("IAM", "WARNING"),
    "REVIEW_BUDGET_ALERTS": ("BUDGETS", "WARNING"),
    "REVIEW_BUDGETS_EXCEEDED": ("BUDGETS", "WARNING"),
    "REVIEW_FREETIER_USAGE_ALERTS": ("FREE_TIER", "WARNING"),
    "REVIEW_ANOMALIES": ("COST_ANOMALY_DETECTION", "WARNING"),
    "REVIEW_EXPIRING_RI": ("RESERVATIONS", "WARNING"),
    "REVIEW_EXPIRING_SP": ("SAVINGS_PLANS", "WARNING"),
    "PAYMENTS_DUE": ("PAYMENTS", "INFO"),
    "REVIEW_SAVINGS_OPPORTUNITY_RECOMMENDATIONS": ("COST_OPTIMIZATION_HUB", "INFO"),
    "ENABLE_COST_OPTIMIZATION_HUB": ("COST_OPTIMIZATION_HUB", "INFO"),
    "CREATE_BUDGET": ("BUDGETS", "INFO"),
    "ADD_ALTERNATE_BILLING_CONTACT": ("ACCOUNT", "INFO"),
    "CREATE_ANOMALY_MONITOR": ("COST_ANOMALY_DETECTION", "INFO"),
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every returned action whose type is one of the documented, fixed
    action types carries the documented feature and severity for that type."""
    client = ctx.client("bcm-recommended-actions")
    resp = client.list_recommended_actions(maxResults=1000)
    actions = resp["recommendedActions"]

    checked = 0
    for action in actions:
        mapping = _TYPE_TO_FEATURE_SEVERITY.get(action["type"])
        if mapping is None:
            continue
        expected_feature, expected_severity = mapping
        assert action["feature"] == expected_feature, (action["type"], action["feature"])
        assert action["severity"] == expected_severity, (action["type"], action["severity"])
        checked += 1

    # The mapping assertion above holds trivially if no documented type is present -- there is no
    # write API for this service, so a type cannot be manufactured to exercise it -- and
    # bcm-recommended-actions has no other feature/severity write path either.
    assert checked > 0, (
        f"none of {len(actions)} recommended action(s) had a documented type; "
        "needs a sandbox account with at least one naturally-occurring action of a "
        f"type in {sorted(_TYPE_TO_FEATURE_SEVERITY)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
