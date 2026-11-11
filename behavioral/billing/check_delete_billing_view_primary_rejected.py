"""delete-billing-view-primary-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-billing-view-primary-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


_ARN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'arn' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: "
    r"arn:aws[a-z-]*:(billing)::[0-9]{12}:billingview/[a-zA-Z0-9/:_\+=\.\-@]{0,75}[a-zA-Z0-9]"
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBillingView on the PRIMARY view fails with ValidationException "... Only Custom Billing
    Views may be deleted.", distinct from the ARN-pattern message a malformed arn gets, and
    GetBillingView afterwards still returns the PRIMARY view."""
    billing = ctx.client("billing")
    primary_arn = _primary_view_arn(ctx)

    fmt_code, fmt_message = _error(lambda: billing.delete_billing_view(arn="not-an-arn-at-all"))
    assert fmt_code == "ValidationException", fmt_code
    assert fmt_message == _ARN_PATTERN_MESSAGE, fmt_message

    code, message = _error(lambda: billing.delete_billing_view(arn=primary_arn))
    assert code == "ValidationException", code
    assert message == (
        "The Billing View ARN does not correspond to a Custom Billing View. "
        "Only Custom Billing Views may be deleted."
    ), message
    assert message != fmt_message, (
        f"primary-view rejection should not be the arn-format message: {message!r}"
    )

    # effect absent: the PRIMARY view is still there and still healthy
    still_there = billing.get_billing_view(arn=primary_arn)["billingView"]
    assert still_there["arn"] == primary_arn
    assert still_there["billingViewType"] == "PRIMARY"


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
