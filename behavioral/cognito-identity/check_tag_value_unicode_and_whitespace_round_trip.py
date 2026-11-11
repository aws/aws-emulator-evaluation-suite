"""tag-value-unicode-and-whitespace-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-and-whitespace-round-trip"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag keys/values with unicode and leading/trailing whitespace persist
    byte-identical through TagResource and ListTagsForResource."""
    ci = ctx.client("cognito-identity")
    pool_id = _create_pool(ctx)
    arn = _pool_arn(ctx, pool_id)

    # TagValueType/TagKeysType only constrain length, not character set, so unicode
    # and whitespace (including leading/trailing) should survive verbatim.
    tag_key = "  \u94a5 key-\u30c6\u30b9\u30c8  "
    tag_value = "  valeur-sp\u00e9ciale \u03a9 \u65e5\u672c   caf\u00e9  "

    ci.tag_resource(ResourceArn=arn, Tags={tag_key: tag_value})

    listed = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tag_key in listed, f"tag key {tag_key!r} missing from ListTagsForResource: {listed!r}"
    assert listed[tag_key] == tag_value, (
        f"tag value mismatch: {listed[tag_key]!r} != {tag_value!r}"
    )


def _create_pool(ctx) -> str:
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real pool "),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _pool_arn(ctx, pool_id: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
