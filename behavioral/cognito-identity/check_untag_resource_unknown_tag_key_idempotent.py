"""untag-resource-unknown-tag-key-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-unknown-tag-key-idempotent"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a tag key that was never set succeeds (idempotent removal)."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    arn = _pool_arn(ctx, pool_id)

    ci.tag_resource(ResourceArn=arn, Tags={"present-key": "present-value"})

    # "never-configured-key" was never set on this pool; removing it must not error.
    resp = ci.untag_resource(ResourceArn=arn, TagKeys=["never-configured-key"])
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200 removing an unset tag key, got {status}"

    tags_after = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_after == {"present-key": "present-value"}, (
        f"unrelated tag state should be untouched, got {tags_after}"
    )

    # Removing the same never-configured key a second time is also a no-op success.
    ci.untag_resource(ResourceArn=arn, TagKeys=["never-configured-key"])
    tags_still = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_still == {"present-key": "present-value"}, (
        f"repeat untag of an already-absent key should still leave tags untouched, got {tags_still}"
    )


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
