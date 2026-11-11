"""update-billing-preferences-access-denied-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-billing-preferences-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateBillingPreferences for RI_SHARING and RI_SHARING_HISTORY fails with AccessDeniedException
    "... No access to feature <feature>" for a caller without Billing console access, while the same
    caller's GetBillingPreferences for CREDIT_SHARING succeeds."""
    billing = ctx.client("billing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resp = billing.get_billing_preferences(features=["CREDIT_SHARING"])
    assert "billingPreferences" in resp, resp
    assert isinstance(resp["billingPreferences"], list), resp["billingPreferences"]

    code, message = _error(
        lambda: billing.update_billing_preferences(
            feature="RI_SHARING",
            billingPreferencesPerKey=[{"key": "sim2real-test-key", "value": "ENABLED"}],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == _denied_message(account_id, "RI_SHARING"), message

    code2, message2 = _error(
        lambda: billing.update_billing_preferences(
            feature="RI_SHARING_HISTORY",
            billingPreferencesPerKey=[{"key": "sim2real-test-key", "value": "ENABLED"}],
        )
    )
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}"
    assert message2 == _denied_message(account_id, "RI_SHARING_HISTORY"), message2


def _denied_message(account_id, feature):
    return (
        f"[Exception=AccessDeniedException][AccountId = {account_id}]"
        f"[Operation = UpdateBillingPreferencesPaperwork][Message=No access to feature {feature}]"
    )


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

