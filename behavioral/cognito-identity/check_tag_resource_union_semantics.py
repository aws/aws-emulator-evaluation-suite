"""tag-resource-union-semantics."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-union-semantics"
GROUP = "tagging"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource is a union/merge by key: a second call adds new keys and overwrites an
    existing key's value, while leaving other previously-set keys untouched."""
    ci = ctx.client("cognito-identity")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"Owner": "team-a", "Region": "us-west"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    arn = f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"

    initial = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert initial == {"Owner": "team-a", "Region": "us-west"}, initial

    # "Region" is named by neither call below: only a true union/merge leaves it in place.
    # A target that fully replaced the tag set on TagResource (instead of merging by key)
    # would drop it here.
    ci.tag_resource(ResourceArn=arn, Tags={"Owner": "team-b", "Env": "test"})

    tags = ci.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags == {"Owner": "team-b", "Env": "test", "Region": "us-west"}, tags


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
