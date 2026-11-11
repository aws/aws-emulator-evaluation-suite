"""update-tags-for-resource-add-remove."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "update-tags-for-resource-add-remove"
GROUP = 'environment-data-plane'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTagsForResource can both add a new tag and remove an existing one."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    resp = eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))
    app_arn = resp["Application"]["ApplicationArn"]

    eb.update_tags_for_resource(
        ResourceArn=app_arn,
        TagsToAdd=[{"Key": "keep-me", "Value": "1"}, {"Key": "remove-me", "Value": "1"}],
    )
    eb.update_tags_for_resource(
        ResourceArn=app_arn,
        TagsToAdd=[{"Key": "keep-me", "Value": "2"}],
        TagsToRemove=["remove-me"],
    )

    tags_resp = eb.list_tags_for_resource(ResourceArn=app_arn)
    tags = {t["Key"]: t["Value"] for t in tags_resp["ResourceTags"]}
    assert tags.get("keep-me") == "2", "tag value must be updated by TagsToAdd"
    assert "remove-me" not in tags, "tag listed in TagsToRemove must be gone"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
