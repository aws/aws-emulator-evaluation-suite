"""update-billing-view-nonexistent-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-billing-view-nonexistent-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["billing"]


_NOT_CUSTOM_MESSAGE = (
    "The Billing View ARN does not correspond to a Custom Billing View. "
    "Only Custom Billing Views may be edited."
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateBillingView on a well-formed but nonexistent arn and on the PRIMARY view both fail with the same
    ValidationException "... Only Custom Billing Views may be edited.", and the PRIMARY view's name and
    description are unchanged afterwards."""
    billing = ctx.client("billing")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    primary_arn = _primary_view_arn(ctx)

    # positive control: real, working billing read access to this exact
    # resource -- rules out "everything about billing is denied"
    before = billing.get_billing_view(arn=primary_arn)["billingView"]
    assert before["billingViewType"] == "PRIMARY", before["billingViewType"]

    # negative: well-formed but nonexistent billingview id
    fake_arn = f"arn:aws:billing::{account_id}:billingview/sim2real-behav-does-not-exist"
    code, msg = _error(
        lambda: billing.update_billing_view(arn=fake_arn, name=ctx.unique_name("sim2real-behav-"))
    )
    assert code == "ValidationException", code
    assert msg == _NOT_CUSTOM_MESSAGE, msg

    # negative: the PRIMARY view is not a CUSTOM view either -- AWS
    # rejects it with the *identical* code and message as the nonexistent arn
    # above, not a distinct not-found-vs-ineligible pair
    code2, msg2 = _error(
        lambda: billing.update_billing_view(arn=primary_arn, name=ctx.unique_name("sim2real-behav-"))
    )
    assert code2 == "ValidationException", code2
    assert msg2 == _NOT_CUSTOM_MESSAGE, msg2

    # effect absent: the real PRIMARY view is provably untouched by either
    # failed call, not just "still typed PRIMARY"
    after = billing.get_billing_view(arn=primary_arn)["billingView"]
    assert after["name"] == before["name"], (before["name"], after["name"])
    assert after["description"] == before["description"], (before["description"], after["description"])


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

