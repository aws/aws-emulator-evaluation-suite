"""tag-operations-nonexistent-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-operations-nonexistent-resource-not-found"
GROUP = "overly-permissive"
SERVICES = ["billingconductor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, ListTagsForResource and UntagResource on a well-formed but nonexistent pricing rule ARN
    each fail with NotFoundException "Resource was not found", while ListTagsForResource on the AWS-managed
    Passthrough pricing plan does not answer NotFoundException."""
    bc = ctx.client("billingconductor")
    account_id = _caller_account_id(ctx)
    fake_rule_arn = f"arn:aws:billingconductor::{account_id}:pricingrule/BOGUS0000A"

    # Positive control: a non-payer account cannot create a pricing rule of its own
    # (CreatePricingRule is payer-account-gated), so the only real, always-present
    # resource available to probe is AWS's own managed default pricing plan.
    # ListTagsForResource against it must NOT read as not-found -- otherwise
    # "always return NotFoundException" would satisfy the assertions below
    # regardless of whether existence is actually being checked.
    control_code, control_msg = _error_info(
        lambda: bc.list_tags_for_resource(
            ResourceArn="arn:aws:billingconductor::aws:pricingplan/Passthrough"
        )
    )
    assert control_code != "NotFoundException", (
        f"positive control: a real, AWS-managed pricing plan must not read as "
        f"not-found ({control_code}: {control_msg})"
    )

    tag_code, tag_msg = _error_info(
        lambda: bc.tag_resource(ResourceArn=fake_rule_arn, Tags={"env": "sim2real"})
    )
    assert tag_code == "NotFoundException", f"unexpected TagResource code: {tag_code} ({tag_msg})"
    assert tag_msg == "Resource was not found", f"unexpected TagResource message: {tag_msg!r}"

    list_code, list_msg = _error_info(
        lambda: bc.list_tags_for_resource(ResourceArn=fake_rule_arn)
    )
    assert list_code == "NotFoundException", (
        f"unexpected ListTagsForResource code: {list_code} ({list_msg})"
    )
    assert list_msg == "Resource was not found", (
        f"unexpected ListTagsForResource message: {list_msg!r}"
    )

    untag_code, untag_msg = _error_info(
        lambda: bc.untag_resource(ResourceArn=fake_rule_arn, TagKeys=["env"])
    )
    assert untag_code == "NotFoundException", (
        f"unexpected UntagResource code: {untag_code} ({untag_msg})"
    )
    assert untag_msg == "Resource was not found", (
        f"unexpected UntagResource message: {untag_msg!r}"
    )


def _caller_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _error_info(fn):
    """Call fn() and return its error (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return (err["Code"], err.get("Message"))
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
