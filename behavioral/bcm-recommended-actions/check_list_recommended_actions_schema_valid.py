"""list-recommended-actions-schema-valid."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "list-recommended-actions-schema-valid"
GROUP = "smoke"
SERVICES = ["bcm-recommended-actions"]

_ACTION_TYPES = {
    "ADD_ALTERNATE_BILLING_CONTACT", "CREATE_ANOMALY_MONITOR", "CREATE_BUDGET",
    "ENABLE_COST_OPTIMIZATION_HUB", "MIGRATE_TO_GRANULAR_PERMISSIONS", "PAYMENTS_DUE",
    "PAYMENTS_PAST_DUE", "REVIEW_ANOMALIES", "REVIEW_BUDGET_ALERTS",
    "REVIEW_BUDGETS_EXCEEDED", "REVIEW_EXPIRING_RI", "REVIEW_EXPIRING_SP",
    "REVIEW_FREETIER_USAGE_ALERTS", "REVIEW_FREETIER_CREDITS_REMAINING",
    "REVIEW_FREETIER_DAYS_REMAINING", "REVIEW_SAVINGS_OPPORTUNITY_RECOMMENDATIONS",
    "UPDATE_EXPIRED_PAYMENT_METHOD", "UPDATE_INVALID_PAYMENT_METHOD",
    "UPDATE_TAX_EXEMPTION_CERTIFICATE", "UPDATE_TAX_REGISTRATION_NUMBER",
}
_SEVERITIES = {"INFO", "WARNING", "CRITICAL"}
_FEATURES = {
    "ACCOUNT", "BUDGETS", "COST_ANOMALY_DETECTION", "COST_OPTIMIZATION_HUB",
    "FREE_TIER", "IAM", "PAYMENTS", "RESERVATIONS", "SAVINGS_PLANS", "TAX_SETTINGS",
}
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unfiltered ListRecommendedActions returns a list whose every action has a non-empty id, a modeled
    type, severity and feature, a 12-digit accountId and correctly typed optional fields, with any
    nextToken 1-8192 characters long."""
    client = ctx.client("bcm-recommended-actions")
    resp = client.list_recommended_actions()

    assert "recommendedActions" in resp, f"response missing recommendedActions: {sorted(resp)}"
    actions = resp["recommendedActions"]
    assert isinstance(actions, list), f"recommendedActions is not a list: {type(actions).__name__}"

    if "nextToken" in resp and resp["nextToken"] is not None:
        next_token = resp["nextToken"]
        assert 1 <= len(next_token) <= 8192, f"nextToken length out of bounds: {len(next_token)}"

    for action in actions:
        action_id = action.get("id")
        assert isinstance(action_id, str) and len(action_id) > 0, f"missing/empty id: {action!r}"

        assert "type" in action, f"action {action_id} missing type"
        assert action["type"] in _ACTION_TYPES, f"action {action_id} unknown type: {action['type']!r}"

        assert "severity" in action, f"action {action_id} missing severity"
        assert action["severity"] in _SEVERITIES, (
            f"action {action_id} unknown severity: {action['severity']!r}"
        )

        assert "feature" in action, f"action {action_id} missing feature"
        assert action["feature"] in _FEATURES, f"action {action_id} unknown feature: {action['feature']!r}"

        assert "accountId" in action, f"action {action_id} missing accountId"
        assert _ACCOUNT_ID_RE.match(action["accountId"]), (
            f"action {action_id} malformed accountId: {action['accountId']!r}"
        )

        if "context" in action and action["context"] is not None:
            context = action["context"]
            assert isinstance(context, dict), f"action {action_id} context is not a dict: {context!r}"
            for key, value in context.items():
                assert isinstance(key, str), f"action {action_id} context key not a string: {key!r}"
                assert isinstance(value, str), f"action {action_id} context[{key!r}] not a string: {value!r}"

        if "nextSteps" in action and action["nextSteps"] is not None:
            next_steps = action["nextSteps"]
            assert isinstance(next_steps, list), f"action {action_id} nextSteps is not a list: {next_steps!r}"
            for step in next_steps:
                assert isinstance(step, str), f"action {action_id} nextSteps entry not a string: {step!r}"

        if "lastUpdatedTimeStamp" in action and action["lastUpdatedTimeStamp"] is not None:
            ts = action["lastUpdatedTimeStamp"]
            assert isinstance(ts, str), f"action {action_id} lastUpdatedTimeStamp is not a string: {ts!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
