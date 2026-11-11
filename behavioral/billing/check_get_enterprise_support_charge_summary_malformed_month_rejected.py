"""get-enterprise-support-charge-summary-malformed-month-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-enterprise-support-charge-summary-malformed-month-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


_MONTH_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'billingMonth' failed to satisfy constraint: "
    r"Member must satisfy regular expression pattern: \d{4}-(0[1-9]|1[0-2])"
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetEnterpriseSupportChargeSummary with billingMonth "2024-13" or "not-a-month" fails with
    ValidationException carrying the exact billingMonth pattern message, while "2024-01" passes
    the pattern check (it succeeds or fails with a code other than ValidationException)."""
    billing = ctx.client("billing")

    # negative: month 13 does not exist, so success is never a legitimate outcome
    code, message = _error(lambda: billing.get_enterprise_support_charge_summary(billingMonth="2024-13"))
    assert code == "ValidationException", code
    assert message == _MONTH_PATTERN_MESSAGE, message

    # negative: non-numeric / wrong shape entirely
    code2, message2 = _error(lambda: billing.get_enterprise_support_charge_summary(billingMonth="not-a-month"))
    assert code2 == "ValidationException", code2
    assert message2 == _MONTH_PATTERN_MESSAGE, message2

    # positive control: a well-formed month passes the pattern check (whatever
    # happens afterwards -- success, AccessDenied, or ResourceNotFound -- it is
    # NOT a ValidationException about the shape of billingMonth), so success is a
    # legitimate outcome here and must not raise
    from botocore.exceptions import ClientError

    try:
        billing.get_enterprise_support_charge_summary(billingMonth="2024-01")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] != "ValidationException", exc.response["Error"]


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

