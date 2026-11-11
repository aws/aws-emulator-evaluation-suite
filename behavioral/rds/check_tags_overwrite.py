"""tags-overwrite."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tags-overwrite"
GROUP = 'tags'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Adding a tag with an existing key overwrites the value."""
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
    rds.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": "version", "Value": "v1"}])
    rds.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": "version", "Value": "v2"}])
    tag_resp = rds.list_tags_for_resource(ResourceName=arn)
    raw_tags = tag_resp["TagList"]
    version_entries = [t for t in raw_tags if t["Key"] == "version"]
    assert len(version_entries) == 1, (
        f"expected exactly one 'version' tag entry after overwrite, got {version_entries}"
    )
    assert version_entries[0]["Value"] == "v2", (
        f"expected 'version' tag to be overwritten to 'v2', got {version_entries[0]['Value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
