"""untag-nonexistent-tag-is-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-nonexistent-tag-is-noop"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource for a key that was never set succeeds and leaves existing tags unaffected."""
    ci = ctx.client("cognito-identity")
    pool_id = _create_pool(ctx)
    arn = _pool_arn(ctx, pool_id)

    ci.tag_resource(ResourceArn=arn, Tags={"Keep": "yes"})
    tags = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags == {"Keep": "yes"}, tags

    # removing a key that was never set must not raise and must not disturb existing tags
    resp = ci.untag_resource(ResourceArn=arn, TagKeys=["NeverSet"])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, resp

    tags_after = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_after == {"Keep": "yes"}, tags_after

    # the no-op is repeatable, not a one-time fluke
    ci.untag_resource(ResourceArn=arn, TagKeys=["NeverSet"])
    tags_still = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_still == {"Keep": "yes"}, tags_still


def _create_pool(ctx, **extra) -> str:
    ci = ctx.client("cognito-identity")
    name = extra.pop("IdentityPoolName", None) or ctx.unique_name("sim2real-behav-")
    allow_unauth = extra.pop("AllowUnauthenticatedIdentities", True)
    resp = ci.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **extra
    )
    pool_id = resp["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
