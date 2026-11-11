"""list-tags-for-resource-empty-by-default."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-empty-by-default"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created identity pool has no tags until TagResource is called."""
    ci = ctx.client("cognito-identity")
    pool_id = _create_pool(ctx, ci)
    pool_arn = _pool_arn(ctx, pool_id)

    listed = ci.list_tags_for_resource(ResourceArn=pool_arn)
    assert listed.get("Tags", {}) == {}, f"expected no tags on a fresh pool, got {listed}"

    # Positive control: prove ListTagsForResource can report a non-empty result on this same
    # pool, so the empty reading above is a real observation and not a target that always
    # answers empty regardless of state.
    ci.tag_resource(ResourceArn=pool_arn, Tags={"sim2real-probe": "present"})
    after_tag = ci.list_tags_for_resource(ResourceArn=pool_arn).get("Tags", {})
    assert after_tag.get("sim2real-probe") == "present", (
        f"expected tag visible after TagResource, got {after_tag}"
    )


def _create_pool(ctx, ci, *, unauth: bool = True) -> str:
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=unauth,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
