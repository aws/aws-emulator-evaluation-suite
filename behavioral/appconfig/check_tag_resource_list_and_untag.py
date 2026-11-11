"""tag-resource-list-and-untag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-and-untag"
GROUP = 'tagging'
SERVICES = ['appconfig']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags applied to an application are visible via ListTagsForResource and removable."""
    ac = ctx.client("appconfig")
    account = ctx.client("sts").get_caller_identity()["Account"]
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: ac.delete_application(ApplicationId=app_id))
    account_arn = f"arn:aws:appconfig:{ctx.region}:{account}:application/{app_id}"

    ac.tag_resource(ResourceArn=account_arn, Tags={"env": "test", "owner": "fidelity-suite"})
    tags = ac.list_tags_for_resource(ResourceArn=account_arn)["Tags"]
    assert tags == {"env": "test", "owner": "fidelity-suite"}, f"expected exactly the applied tags, got {tags}"

    ac.untag_resource(ResourceArn=account_arn, TagKeys=["env"])
    tags_after = ac.list_tags_for_resource(ResourceArn=account_arn)["Tags"]
    assert tags_after == {"owner": "fidelity-suite"}, f"expected only 'owner' to survive untag, got {tags_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
