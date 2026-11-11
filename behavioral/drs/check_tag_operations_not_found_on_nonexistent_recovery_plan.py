"""tag-operations-not-found-on-nonexistent-recovery-plan."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-operations-not-found-on-nonexistent-recovery-plan"
GROUP = "overly-permissive"
SERVICES = ["drs"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "requires:drs-initialized",
)
def run(ctx) -> None:
    """Tag/List/UntagResource on a nonexistent recovery plan ARN fail with NotFoundException --
    unlike the ResourceNotFoundException Get/Update/Delete raise for the same missing plan --
    while the same calls against a real plan succeed.
    """
    drs = ctx.client("drs")
    account = ctx.account
    fake_arn = (
        f"arn:aws:drs:{ctx.region}:{account}:recovery-plan/plan-00000000000000000000000000000000"
    )

    code, message = _expect_rejected(
        lambda: drs.tag_resource(resourceArn=fake_arn, tags={"sim2real-key": "sim2real-value"})
    )
    assert code == "NotFoundException", f"TagResource on a nonexistent plan ARN got {code!r}"
    assert message == "Resource was not found", (
        f"TagResource on a nonexistent plan ARN answered {message!r}"
    )

    code, message = _expect_rejected(lambda: drs.list_tags_for_resource(resourceArn=fake_arn))
    assert code == "NotFoundException", (
        f"ListTagsForResource on a nonexistent plan ARN got {code!r}"
    )
    assert message == "Resource was not found", (
        f"ListTagsForResource on a nonexistent plan ARN answered {message!r}"
    )

    code, message = _expect_rejected(
        lambda: drs.untag_resource(resourceArn=fake_arn, tagKeys=["sim2real-key"])
    )
    assert code == "NotFoundException", f"UntagResource on a nonexistent plan ARN got {code!r}"
    assert message == "Resource was not found", (
        f"UntagResource on a nonexistent plan ARN answered {message!r}"
    )

    # Positive control: the identical calls against a real recovery plan succeed.
    name = ctx.unique_name("sim2real-drs-rp-tagtest-")
    created = drs.create_recovery_plan(name=name)["recoveryPlan"]
    rp_arn = created["recoveryPlanArn"]
    ctx.on_cleanup(lambda: _delete_plan(drs, rp_arn))

    drs.tag_resource(resourceArn=rp_arn, tags={"sim2real-key": "sim2real-value"})
    real_tags = drs.list_tags_for_resource(resourceArn=rp_arn)["tags"]
    assert real_tags == {"sim2real-key": "sim2real-value"}, (
        f"TagResource/ListTagsForResource against a real plan must succeed, got {real_tags!r}"
    )


def _expect_rejected(fn):
    try:
        result = fn()
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")


def _delete_plan(drs, rp_arn: str) -> None:
    try:
        drs.delete_recovery_plan(recoveryPlanArn=rp_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
