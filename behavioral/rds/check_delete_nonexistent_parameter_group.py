"""delete-nonexistent-parameter-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-parameter-group"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_PARAMETER_GROUP_NOT_FOUND = "DBParameterGroupNotFound"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBParameterGroup for a name that was never created raises NotFound,
    and an independent read (Describe, not Delete) agrees the name is absent."""
    rds = ctx.client("rds")

    # Positive control: prove parameter-group operations work in this account
    # first, so the NotFound below means "this name never existed" rather than
    # "this account rejects DeleteDBParameterGroup unconditionally".
    real_name = ctx.unique_name("sim2real-behav-pg-real-")
    rds.create_db_parameter_group(
        DBParameterGroupName=real_name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=real_name))

    ghost = ctx.unique_name("sim2real-behav-pg-ghost-")

    delete_code, delete_message = _error_code(lambda: rds.delete_db_parameter_group(DBParameterGroupName=ghost))
    assert delete_code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_PARAMETER_GROUP_NOT_FOUND} on delete, got {delete_code!r}"
    )
    assert delete_message == f"DBParameterGroup not found: {ghost}", delete_message

    describe_code, describe_message = _error_code(
        lambda: rds.describe_db_parameter_groups(DBParameterGroupName=ghost)
    )
    assert describe_code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, (
        f"expected {ERR_DB_PARAMETER_GROUP_NOT_FOUND} on independent describe read, "
        f"got {describe_code!r}"
    )
    assert describe_message == f"DBParameterGroup not found: {ghost}", describe_message


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
