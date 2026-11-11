"""tag-resource-empty-string-value-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-empty-string-value-preserved"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag with an empty-string value is preserved distinctly from an absent tag when listed
    via ListTagsForResource."""
    ci = ctx.client("cognito-identity")
    sts = ctx.client("sts")

    pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    account_id = sts.get_caller_identity()["Account"]
    pool_arn = f"arn:aws:cognito-identity:{ctx.region}:{account_id}:identitypool/{pool_id}"

    ci.tag_resource(ResourceArn=pool_arn, Tags={"EmptyValueTag": ""})

    listed = ci.list_tags_for_resource(ResourceArn=pool_arn)["Tags"]
    assert "EmptyValueTag" in listed, "tag with empty-string value vanished (treated as absent)"
    assert listed["EmptyValueTag"] == "", f"empty-string tag value was mutated: {listed['EmptyValueTag']!r}"
    assert "NeverSetTag" not in listed, "an untagged key spuriously appeared in ListTagsForResource"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
