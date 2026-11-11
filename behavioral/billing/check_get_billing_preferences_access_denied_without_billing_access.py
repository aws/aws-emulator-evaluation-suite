"""get-billing-preferences-access-denied-without-billing-access."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-billing-preferences-access-denied-without-billing-access"
GROUP = "overly-permissive"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBillingPreferences for BILLING_ALERTS and RI_SHARING_HISTORY fails with AccessDeniedException
    "... No access to feature <feature>" for a caller without Billing console access, while
    CREDIT_SHARING succeeds for the same caller, so the gate is per feature."""
    billing = ctx.client("billing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    for feature in ("BILLING_ALERTS", "RI_SHARING_HISTORY"):
        code, message = _error(
            lambda feature=feature: billing.get_billing_preferences(features=[feature])
        )
        assert code == "AccessDeniedException", (feature, code, message)
        # ties the denial to this specific feature, not a blanket/malformed-request
        # rejection
        assert message == (
            f"[Exception=AccessDeniedException][AccountId = {account_id}]"
            f"[Operation = GetBillingPreferencesPaperwork][Message=No access to feature {feature}]"
        ), (feature, message)

    # positive control: a feature that does not require billing console
    # access activation succeeds for the very same caller
    resp = billing.get_billing_preferences(features=["CREDIT_SHARING"])
    assert "billingPreferences" in resp
    assert isinstance(resp["billingPreferences"], list)


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


