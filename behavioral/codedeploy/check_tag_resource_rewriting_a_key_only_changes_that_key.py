"""tag-resource-rewriting-a-key-only-changes-that-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-rewriting-a-key-only-changes-that-key"
GROUP = "tags"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource re-sending a key already on the resource replaces only that key's
    value; a tag set at create time and one set by an earlier TagResource call survive.
    """
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cdapp-")
    cd.create_application(
        applicationName=name,
        computePlatform="Server",
        tags=[{"Key": "Pipeline", "Value": "alpha"}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    arn = f"arn:aws:codedeploy:{ctx.region}:{ctx.account}:application:{name}"

    cd.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": "Owner", "Value": "teamA"}, {"Key": "Component", "Value": "worker"}],
    )
    after_first = {t["Key"]: t["Value"] for t in cd.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert after_first == {"Pipeline": "alpha", "Owner": "teamA", "Component": "worker"}, (
        f"tags after the first TagResource call were {after_first!r}"
    )

    cd.tag_resource(ResourceArn=arn, Tags=[{"Key": "Owner", "Value": "teamB"}])
    after_second = {t["Key"]: t["Value"] for t in cd.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert after_second == {"Pipeline": "alpha", "Owner": "teamB", "Component": "worker"}, (
        f"re-sending Owner changed the tag set to {after_second!r}, expected only Owner's "
        f"value to change from 'teamA' to 'teamB'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
