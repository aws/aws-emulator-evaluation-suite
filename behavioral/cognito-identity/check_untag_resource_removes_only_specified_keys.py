"""untag-resource-removes-only-specified-keys."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-only-specified-keys"
GROUP = "tagging"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the keys listed in TagKeys, leaving all other tags intact."""
    ci = ctx.client("cognito-identity")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"Owner": "team-a", "Env": "test", "Keep": "yes"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    arn = f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"

    ci.untag_resource(ResourceArn=arn, TagKeys=["Owner", "Env"])

    tags = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags == {"Keep": "yes"}, f"expected only the untargeted key to survive, got {tags}"

    pool_tags = ci.describe_identity_pool(IdentityPoolId=pool_id)["IdentityPoolTags"]
    assert pool_tags == {"Keep": "yes"}, (
        f"DescribeIdentityPool disagrees with ListTagsForResource: {pool_tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
