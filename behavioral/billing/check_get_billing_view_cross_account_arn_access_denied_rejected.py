"""get-billing-view-cross-account-arn-access-denied-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-billing-view-cross-account-arn-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBillingView on a well-formed billing-view ARN of another account fails with AccessDeniedException
    "... because no resource-based policy allows the billing:GetBillingView action", while the caller's own
    PRIMARY view is readable and owned by its account."""
    billing = ctx.client("billing")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    own_account_id = identity["Account"]

    # positive control: the caller's own PRIMARY view is readable
    own_views = billing.list_billing_views(billingViewTypes=["PRIMARY"])["billingViews"]
    assert len(own_views) == 1, f"expected exactly one PRIMARY billing view, got {own_views!r}"
    own_view = billing.get_billing_view(arn=own_views[0]["arn"])["billingView"]
    assert own_view["ownerAccountId"] == own_account_id, (
        f"expected ownerAccountId {own_account_id!r}, got {own_view['ownerAccountId']!r}"
    )

    # break exactly one thing: address a well-formed billing-view ARN scoped to a
    # foreign account rather than the caller's own
    foreign_account_id = "111122223333"
    assert foreign_account_id != own_account_id, (
        "fixture foreign account id collides with the caller's own account"
    )
    foreign_arn = f"arn:aws:billing::{foreign_account_id}:billingview/primary"
    code, message = _error(lambda: billing.get_billing_view(arn=foreign_arn))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a cross-account billing-view ARN, got {code!r}"
    )
    assert message == (
        f"User: {identity['Arn']} is not authorized to perform: billing:GetBillingView on resource: "
        f"{foreign_arn} because no resource-based policy allows the billing:GetBillingView action"
    ), message


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
