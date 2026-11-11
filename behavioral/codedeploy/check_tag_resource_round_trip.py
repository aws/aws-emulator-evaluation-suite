"""tag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "tag-resource-round-trip"
GROUP = 'tags'
SERVICES = ['codedeploy']

def _account_id(ctx):
    cached = getattr(ctx, "_cd_account_id", None)
    if cached is None:
        cached = ctx.account
        ctx._cd_account_id = cached
    return cached


def _application_arn(ctx, name):
    return f"arn:aws:codedeploy:{ctx.region}:{_account_id(ctx)}:application:{name}"


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(applicationName=name, computePlatform=compute_platform)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource -> ListTagsForResource -> UntagResource on an application ARN."""
    cd = ctx.client("codedeploy")
    name = _create_application(ctx)
    arn = _application_arn(ctx, name)

    cd.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": "Team", "Value": "probe"}, {"Key": "Env", "Value": "dev"}],
    )
    tags = cd.list_tags_for_resource(ResourceArn=arn)["Tags"]
    kv = {t["Key"]: t["Value"] for t in tags}
    assert kv.get("Team") == "probe", tags
    assert kv.get("Env") == "dev", tags
    assert kv == {"Team": "probe", "Env": "dev"}, tags

    cd.untag_resource(ResourceArn=arn, TagKeys=["Env"])
    tags2 = cd.list_tags_for_resource(ResourceArn=arn)["Tags"]
    kv2 = {t["Key"]: t["Value"] for t in tags2}
    assert "Env" not in kv2, tags2
    assert kv2.get("Team") == "probe", tags2
    assert kv2 == {"Team": "probe"}, tags2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
