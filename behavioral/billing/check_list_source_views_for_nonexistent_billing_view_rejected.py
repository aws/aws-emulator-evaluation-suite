"""list-source-views-for-nonexistent-billing-view-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-source-views-for-nonexistent-billing-view-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSourceViewsForBillingView on a well-formed but nonexistent billingview arn fails with
    ResourceNotFoundException "[<arn>] is an invalid billing view arn" rather than returning an empty
    list, while the same call on the PRIMARY view returns a list."""
    billing = ctx.client("billing")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    primary_arn = _primary_view_arn(ctx)

    fake_arn = f"arn:aws:billing::{account_id}:billingview/sim2real-behav-does-not-exist"
    code, message = _error(lambda: billing.list_source_views_for_billing_view(arn=fake_arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"[{fake_arn}] is an invalid billing view arn", message

    # positive control: the real PRIMARY view resolves and returns a list
    resp = billing.list_source_views_for_billing_view(arn=primary_arn)
    assert isinstance(resp["sourceViews"], list), (
        f"expected list_source_views_for_billing_view on the real PRIMARY arn to "
        f"return a list, got {resp['sourceViews']!r}"
    )


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

