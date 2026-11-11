"""remove-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "remove-tags"
GROUP = 'tags'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTagsFromResource removes specific tags."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=name))
    resp = rds.describe_db_parameter_groups(DBParameterGroupName=name)
    arn = resp["DBParameterGroups"][0]["DBParameterGroupArn"]
    rds.add_tags_to_resource(
        ResourceName=arn,
        Tags=[
            {"Key": "keep-me", "Value": "yes"},
            {"Key": "remove-me", "Value": "bye"},
        ],
    )
    rds.remove_tags_from_resource(ResourceName=arn, TagKeys=["remove-me"])
    tag_resp = rds.list_tags_for_resource(ResourceName=arn)
    tags = {t["Key"]: t["Value"] for t in tag_resp["TagList"]}
    assert "remove-me" not in tags, f"removed tag key still present: {tags!r}"
    assert tags.get("keep-me") == "yes", f"untouched tag key was disturbed by the removal: {tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
