"""tag-resource-overwrites-existing-key-value."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-overwrites-existing-key-value"
GROUP = "user-pool-tagging"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pool created with no tags lists none, and re-tagging an existing key with a new
    value replaces it rather than merging both values under the key."""
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-tro-pool-"))["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    before = idp.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert before == {}, f"a freshly created, untagged pool should list no tags, got {before!r}"

    idp.tag_resource(ResourceArn=pool_arn, Tags={"env": "staging"})
    first = idp.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert first == {"env": "staging"}, f"expected only env=staging, got {first!r}"

    idp.tag_resource(ResourceArn=pool_arn, Tags={"env": "production"})
    second = idp.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert second == {"env": "production"}, (
        f"re-tagging 'env' should overwrite the value, not merge both, got {second!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
