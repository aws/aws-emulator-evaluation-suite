"""tag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle"
GROUP = 'tags'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """tag_resource adds tags visible via get_tags; untag_resource removes them."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    # Databases are tagged via their catalog ARN.
    region = glue.meta.region_name
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resource_arn = f"arn:aws:glue:{region}:{account_id}:database/{db_name}"

    glue.tag_resource(
        ResourceArn=resource_arn, TagsToAdd={"env": "behavioral-test", "keep": "untouched"}
    )

    resp = glue.get_tags(ResourceArn=resource_arn)
    assert resp["Tags"].get("env") == "behavioral-test", resp["Tags"]
    assert resp["Tags"].get("keep") == "untouched", resp["Tags"]

    glue.untag_resource(ResourceArn=resource_arn, TagsToRemove=["env"])

    resp2 = glue.get_tags(ResourceArn=resource_arn)
    # A second, untouched tag proves untag_resource removes only the named key
    # rather than clearing every tag on the resource.
    assert "env" not in resp2["Tags"], resp2["Tags"]
    assert resp2["Tags"].get("keep") == "untouched", resp2["Tags"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
