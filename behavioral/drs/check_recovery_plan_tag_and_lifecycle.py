"""recovery-plan-tag-and-lifecycle."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recovery-plan-tag-and-lifecycle"
GROUP = "state"
SERVICES = ["drs"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
    "requires:drs-initialized",
)
def run(ctx) -> None:
    """CreateRecoveryPlan persists its name, description and tags; TagResource and UntagResource
    change the tag set in place, each observable through an independent GetRecoveryPlan or
    ListTagsForResource read; DeleteRecoveryPlan then removes it from GetRecoveryPlan.
    """
    drs = ctx.client("drs")
    name = ctx.unique_name("sim2real-drs-rp-")

    created = drs.create_recovery_plan(name=name, tags={"sim2real-a": "1"})["recoveryPlan"]
    rp_arn = created["recoveryPlanArn"]
    ctx.on_cleanup(lambda: _delete_plan(drs, rp_arn))
    assert created["name"] == name, f"expected name={name!r} on create, got {created['name']!r}"
    assert created["tags"] == {"sim2real-a": "1"}, (
        f"expected tags={{'sim2real-a': '1'}} on create, got {created['tags']!r}"
    )

    drs.tag_resource(resourceArn=rp_arn, tags={"sim2real-b": "2"})
    tags_after_add = drs.list_tags_for_resource(resourceArn=rp_arn)["tags"]
    assert tags_after_add == {"sim2real-a": "1", "sim2real-b": "2"}, (
        f"expected both tags present after TagResource, got {tags_after_add!r}"
    )

    drs.untag_resource(resourceArn=rp_arn, tagKeys=["sim2real-a"])
    tags_after_remove = drs.list_tags_for_resource(resourceArn=rp_arn)["tags"]
    assert tags_after_remove == {"sim2real-b": "2"}, (
        f"expected only sim2real-b to remain after UntagResource, got {tags_after_remove!r}"
    )

    drs.update_recovery_plan(recoveryPlanArn=rp_arn, description="sim2real probe description")
    fetched = drs.get_recovery_plan(recoveryPlanArn=rp_arn)["recoveryPlan"]
    assert fetched["description"] == "sim2real probe description", (
        f"expected an independent GetRecoveryPlan read to show the updated description, "
        f"got {fetched.get('description')!r}"
    )

    drs.delete_recovery_plan(recoveryPlanArn=rp_arn)
    code, message = _expect_rejected(lambda: drs.get_recovery_plan(recoveryPlanArn=rp_arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetRecoveryPlan on a deleted plan to raise ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Recovery plan '{rp_arn.rsplit('/', 1)[-1]}' not found.", (
        f"expected the not-found message to name the deleted plan's id, got {message!r}"
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
