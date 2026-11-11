"""create-describe-parameter-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-describe-parameter-group"
GROUP = 'parameter_groups'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBParameterGroup -> DescribeDBParameterGroups returns the group."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=name))
    resp = rds.describe_db_parameter_groups(DBParameterGroupName=name)
    groups = resp["DBParameterGroups"]
    assert len(groups) == 1
    assert groups[0]["DBParameterGroupName"] == name
    assert groups[0]["DBParameterGroupFamily"] == "mysql8.0"
    assert groups[0]["Description"] == "sim2real behavioral test parameter group"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
