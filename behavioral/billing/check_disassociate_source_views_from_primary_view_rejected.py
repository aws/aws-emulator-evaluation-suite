"""disassociate-source-views-from-primary-view-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disassociate-source-views-from-primary-view-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateSourceViews on the PRIMARY billing view fails with ValidationException "Only custom
    billing views can have source views disassociated" rather than succeeding as a no-op, and the view's
    sourceViewCount and ListSourceViewsForBillingView result are unchanged afterwards."""
    billing = ctx.client("billing")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    primary_arn = _primary_view_arn(ctx)

    # positive control: the source-view-association read API answers for the
    # caller's credentials against the real PRIMARY view.
    before_sources = billing.list_source_views_for_billing_view(arn=primary_arn)["sourceViews"]
    before = billing.get_billing_view(arn=primary_arn)["billingView"].get("sourceViewCount", 0)

    fake_source_arn = f"arn:aws:billing::{account_id}:billingview/sim2real-behav-not-a-source"
    code, message = _error(
        lambda: billing.disassociate_source_views(arn=primary_arn, sourceViews=[fake_source_arn])
    )
    assert code == "ValidationException", code
    assert message == "Only custom billing views can have source views disassociated", message

    after = billing.get_billing_view(arn=primary_arn)["billingView"].get("sourceViewCount", 0)
    assert after == before
    after_sources = billing.list_source_views_for_billing_view(arn=primary_arn)["sourceViews"]
    assert after_sources == before_sources


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

