"""tag-resource-list-and-untag-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-and-untag-roundtrip"
GROUP = "state"
SERVICES = ["cognito-identity"]


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on an identity pool ARN."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    arn = _pool_arn(ctx, pool_id)

    tags_before = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_before == {}, f"expected no tags on a fresh pool, got {tags_before}"

    ci.tag_resource(ResourceArn=arn, Tags={"sim2real-env": "qa", "sim2real-team": "cog"})
    tags_after_tag = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_after_tag.get("sim2real-env") == "qa", (
        f"expected sim2real-env=qa after TagResource, got {tags_after_tag}"
    )
    assert tags_after_tag.get("sim2real-team") == "cog", (
        f"expected sim2real-team=cog after TagResource, got {tags_after_tag}"
    )

    ci.untag_resource(ResourceArn=arn, TagKeys=["sim2real-team"])
    tags_after_untag = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_after_untag.get("sim2real-env") == "qa", (
        f"expected untouched key sim2real-env=qa to survive UntagResource, got {tags_after_untag}"
    )
    assert "sim2real-team" not in tags_after_untag, f"untagged key still present: {tags_after_untag}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
