"""list-billing-views-filters-by-arn."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-billing-views-filters-by-arn"
GROUP = "listing"
SERVICES = ["billing"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBillingViews with arns=[PRIMARY view] returns exactly that view; a well-formed but nonexistent
    arn fails with ValidationException "[<arn>] is an invalid billing view arn" rather than being dropped;
    11 arns fail with ValidationException for the length limit of 10."""
    billing = ctx.client("billing")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    primary_arn = _primary_view_arn(ctx)

    result = billing.list_billing_views(arns=[primary_arn])["billingViews"]
    assert len(result) == 1, result
    assert result[0]["arn"] == primary_arn, (result[0]["arn"], primary_arn)

    # negative: a well-formed but nonexistent billing view arn is rejected,
    # not silently filtered out of the results -- the account has only the
    # PRIMARY view, so without this the assertion above would pass even if
    # `arns` were never applied at all.
    fake_arn = f"arn:aws:billing::{account_id}:billingview/sim2real-behav-does-not-exist"
    code, message = _error(lambda: billing.list_billing_views(arns=[fake_arn]))
    assert code == "ValidationException", code
    assert message == f"[{fake_arn}] is an invalid billing view arn", message

    code, message = _error(lambda: billing.list_billing_views(arns=[primary_arn] * 11))
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value at 'arns' failed to satisfy constraint: "
        "Member must have length less than or equal to 10"
    ), message


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


