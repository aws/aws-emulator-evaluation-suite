"""get-billing-view-invalid-arn-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-billing-view-invalid-arn-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


_ARN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'arn' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: "
    r"arn:aws[a-z-]*:(billing)::[0-9]{12}:billingview/[a-zA-Z0-9/:_\+=\.\-@]{0,75}[a-zA-Z0-9]"
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBillingView on an arn that is not an ARN, and on one with a wrong resource segment, fails with
    ValidationException carrying the exact arn-pattern message, while the PRIMARY view's arn resolves."""
    billing = ctx.client("billing")
    primary_arn = _primary_view_arn(ctx)

    # positive control: a real, well-formed arn resolves fine
    detail = billing.get_billing_view(arn=primary_arn)["billingView"]
    assert detail["arn"] == primary_arn, f"expected {primary_arn}, got {detail['arn']}"

    # negative: not an ARN at all
    code, message = _error(lambda: billing.get_billing_view(arn="not-an-arn"))
    assert code == "ValidationException", code
    assert message == _ARN_PATTERN_MESSAGE, message

    # negative: right-shaped ARN but wrong service/resource segment
    malformed = "arn:aws:billing::123456789012:not-a-billingview/abc"
    code, message = _error(lambda: billing.get_billing_view(arn=malformed))
    assert code == "ValidationException", code
    assert message == _ARN_PATTERN_MESSAGE, message


def _primary_view_arn(ctx):
    billing = ctx.client("billing")
    views = billing.list_billing_views(billingViewTypes=["PRIMARY"])["billingViews"]
    assert len(views) == 1, f"expected exactly one PRIMARY billing view, got {len(views)}"
    return views[0]["arn"]


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

