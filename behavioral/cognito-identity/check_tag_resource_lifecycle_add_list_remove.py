"""tag-resource-lifecycle-add-list-remove."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle-add-list-remove"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource -> ListTagsForResource -> UntagResource transitions tag state correctly."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    arn = _pool_arn(ctx, pool_id)

    # No tags yet.
    initial = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert initial == {}, f"expected no tags on fresh pool, got {initial}"

    ci.tag_resource(ResourceArn=arn, Tags={"env": "sim2real-test", "owner": "behavioral-suite"})
    tags = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("env") == "sim2real-test", f"tag not visible after TagResource: {tags}"
    assert tags.get("owner") == "behavioral-suite", f"tag not visible after TagResource: {tags}"

    ci.untag_resource(ResourceArn=arn, TagKeys=["env"])
    tags_after = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "env" not in tags_after, f"expected 'env' removed after UntagResource, got {tags_after}"
    assert tags_after.get("owner") == "behavioral-suite", "unrelated tag was unexpectedly removed"


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
