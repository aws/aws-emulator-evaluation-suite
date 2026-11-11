"""modify-nonexistent-parameter-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-nonexistent-parameter-group"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_PARAMETER_GROUP_NOT_FOUND = "DBParameterGroupNotFound"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyDBParameterGroup for nonexistent raises NotFound; a real group accepts the identical call."""
    rds = ctx.client("rds")

    # Positive control: the identical call, same parameter, against a real
    # group must succeed and take effect — otherwise a target that rejects
    # every ModifyDBParameterGroup call with DBParameterGroupNotFound would
    # pass this check for the wrong reason.
    real_name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=real_name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=real_name))
    rds.modify_db_parameter_group(
        DBParameterGroupName=real_name,
        Parameters=[{'ParameterName': 'max_connections', 'ParameterValue': '100', 'ApplyMethod': 'pending-reboot'}],
    )
    params = {
        p["ParameterName"]: p
        for p in rds.describe_db_parameters(DBParameterGroupName=real_name)["Parameters"]
    }
    if "max_connections" in params:
        assert params["max_connections"].get("ParameterValue") == "100", (
            f"expected max_connections=100 on real group, got {params['max_connections'].get('ParameterValue')!r}"
        )

    ghost = ctx.unique_name("sim2real-behav-pg-")
    try:
        rds.modify_db_parameter_group(DBParameterGroupName=ghost, Parameters=[{'ParameterName': 'max_connections', 'ParameterValue': '100', 'ApplyMethod': 'pending-reboot'}])
        code = message = None
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_PARAMETER_GROUP_NOT_FOUND}, got {code!r}"
    )
    assert message == f"DBParameterGroup not found: {ghost}", message

    # Independent read confirms the ghost group never came into existence.
    try:
        rds.describe_db_parameter_groups(DBParameterGroupName=ghost)
        describe_code = describe_message = None
    except ClientError as _e:
        describe_code = _e.response.get("Error", {}).get("Code")
        describe_message = _e.response.get("Error", {}).get("Message")
    assert describe_code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_PARAMETER_GROUP_NOT_FOUND} on describe, got {describe_code!r}"
    )
    assert describe_message == f"DBParameterGroup not found: {ghost}", describe_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
