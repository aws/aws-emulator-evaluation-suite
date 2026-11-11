"""parameter-group-duplicate-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-group-duplicate-error"
GROUP = 'parameter_groups'
SERVICES = ['rds']

ERR_DB_PARAMETER_GROUP_ALREADY_EXISTS = "DBParameterGroupAlreadyExists"
_FAMILY = "mysql8.0"
_TAGS = [{"Key": "sim2real", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBParameterGroup with an existing name is rejected with DBParameterGroupAlreadyExists and
    leaves the original's description unchanged, a distinct name succeeds, and the original name is
    creatable again after delete."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily=_FAMILY,
        Description="sim2real behavioral test parameter group",
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=name))

    created = rds.describe_db_parameter_groups(DBParameterGroupName=name)["DBParameterGroups"][0]
    assert created["Description"] == "sim2real behavioral test parameter group", created

    code = message = None
    try:
        rds.create_db_parameter_group(
            DBParameterGroupName=name,
            DBParameterGroupFamily=_FAMILY,
            Description="duplicate",
            Tags=_TAGS,
        )
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_DB_PARAMETER_GROUP_ALREADY_EXISTS, (
        f"expected {ERR_DB_PARAMETER_GROUP_ALREADY_EXISTS}, got {code!r}"
    )
    assert message == f"Parameter group {name} already exists", message

    unchanged = rds.describe_db_parameter_groups(DBParameterGroupName=name)["DBParameterGroups"][0]
    assert unchanged["Description"] == "sim2real behavioral test parameter group", (
        f"rejected duplicate mutated the original group: {unchanged['Description']!r}"
    )

    other_name = ctx.unique_name("sim2real-behav-pg-ok-")
    rds.create_db_parameter_group(
        DBParameterGroupName=other_name,
        DBParameterGroupFamily=_FAMILY,
        Description="sim2real control group",
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=other_name))
    control = rds.describe_db_parameter_groups(DBParameterGroupName=other_name)["DBParameterGroups"][0]
    assert control["DBParameterGroupName"].lower() == other_name.lower(), control
    assert control["Description"] == "sim2real control group", control

    rds.delete_db_parameter_group(DBParameterGroupName=name)
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily=_FAMILY,
        Description="sim2real recreated after delete",
        Tags=_TAGS,
    )
    recreated = rds.describe_db_parameter_groups(DBParameterGroupName=name)["DBParameterGroups"][0]
    assert recreated["Description"] == "sim2real recreated after delete", (
        "freeing the name should let an identical create succeed: "
        f"{recreated['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
