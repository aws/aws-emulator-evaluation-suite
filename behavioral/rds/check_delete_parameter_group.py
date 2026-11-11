"""delete-parameter-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-parameter-group"
GROUP = 'parameter_groups'
SERVICES = ['rds']

ERR_DB_PARAMETER_GROUP_NOT_FOUND = "DBParameterGroupNotFound"


def _delete_unless_gone(delete, gone_code):
    """Teardown delete; an already-deleted resource answers ``gone_code`` (documented not-found)."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDBParameterGroup removes the group; an independent Describe raises
    not-found, and a subsequent mutation on the same dead id is rejected the
    same way rather than resurrecting or silently accepting it."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_unless_gone(
        lambda: rds.delete_db_parameter_group(DBParameterGroupName=name), "DBParameterGroupNotFound"))
    rds.delete_db_parameter_group(DBParameterGroupName=name)
    code = message = None
    try:
        rds.describe_db_parameter_groups(DBParameterGroupName=name)
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_PARAMETER_GROUP_NOT_FOUND}, got {code!r}"
    )
    assert message == f"DBParameterGroup not found: {name}", message

    modify_code = modify_message = None
    try:
        rds.modify_db_parameter_group(
            DBParameterGroupName=name,
            Parameters=[{
                "ParameterName": "max_connections",
                "ParameterValue": "100",
                "ApplyMethod": "pending-reboot",
            }],
        )
    except ClientError as _e:
        modify_code = _e.response.get("Error", {}).get("Code")
        modify_message = _e.response.get("Error", {}).get("Message")
    assert modify_code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"expected a mutation on the deleted group to also raise "
        f"{ERR_DB_PARAMETER_GROUP_NOT_FOUND}, got {modify_code!r}"
    )
    assert modify_message == f"DBParameterGroup not found: {name}", modify_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
