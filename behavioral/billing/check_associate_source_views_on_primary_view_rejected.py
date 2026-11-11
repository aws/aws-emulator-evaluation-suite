"""associate-source-views-on-primary-view-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "associate-source-views-on-primary-view-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateSourceViews naming the PRIMARY billing view as its own source fails with
    ValidationException "A billing view cannot be associated to itself", and the view's
    sourceViewCount is unchanged afterwards."""
    billing = ctx.client("billing")
    primary_arn = _primary_view_arn(ctx)

    # positive control: the billing API and credentials are otherwise healthy --
    # a well-formed read against the account's own PRIMARY view resolves fine, so
    # the rejection below is not "everything is denied".
    before = billing.get_billing_view(arn=primary_arn)["billingView"].get("sourceViewCount", 0)

    code, message = _error(
        lambda: billing.associate_source_views(arn=primary_arn, sourceViews=[primary_arn])
    )
    assert code == "ValidationException", code
    assert message == "A billing view cannot be associated to itself", message

    after = billing.get_billing_view(arn=primary_arn)["billingView"].get("sourceViewCount", 0)
    assert after == before, f"sourceViewCount changed: before={before} after={after}"


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

