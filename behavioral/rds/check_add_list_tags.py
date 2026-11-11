"""add-list-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "add-list-tags"
GROUP = 'tags'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTagsToResource -> ListTagsForResource shows the tags."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=name))
    # Get the ARN from describe
    resp = rds.describe_db_parameter_groups(DBParameterGroupName=name)
    arn = resp["DBParameterGroups"][0]["DBParameterGroupArn"]
    # Add tags
    rds.add_tags_to_resource(
        ResourceName=arn,
        Tags=[
            {"Key": "sim2real-key1", "Value": "value1"},
            {"Key": "sim2real-key2", "Value": "value2"},
        ],
    )
    # List tags
    tag_resp = rds.list_tags_for_resource(ResourceName=arn)
    tags = {t["Key"]: t["Value"] for t in tag_resp["TagList"]}
    assert tags.get("sim2real-key1") == "value1", (
        f"expected sim2real-key1=value1, got {tags.get('sim2real-key1')!r}"
    )
    assert tags.get("sim2real-key2") == "value2", (
        f"expected sim2real-key2=value2, got {tags.get('sim2real-key2')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
