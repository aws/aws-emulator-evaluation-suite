"""describe-parameter-groups-list-all."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "describe-parameter-groups-list-all"
GROUP = 'parameter_groups'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBParameterGroups with no name lists every group, not just a filtered one."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-listall-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral list-all test parameter group",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=name))

    resp = rds.describe_db_parameter_groups()
    assert "DBParameterGroups" in resp
    groups = resp["DBParameterGroups"]
    assert isinstance(groups, list)

    by_name = {g["DBParameterGroupName"]: g for g in groups}
    assert name in by_name, f"unfiltered describe missing just-created group {name!r}: saw {sorted(by_name)}"
    assert by_name[name]["DBParameterGroupFamily"] == "mysql8.0", by_name[name]
    assert by_name[name]["Description"] == "sim2real behavioral list-all test parameter group", by_name[name]

    # AWS ships default parameter groups (e.g. default.mysql8.0) in every account; the unfiltered
    # list must carry them alongside what this check created, proving it is not name-scoped.
    assert any(g != name for g in by_name), f"expected pre-existing default groups too, saw only {sorted(by_name)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
