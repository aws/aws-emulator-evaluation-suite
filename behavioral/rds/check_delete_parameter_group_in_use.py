"""delete-parameter-group-in-use."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "delete-parameter-group-in-use"
GROUP = 'parameter_groups'
SERVICES = ['rds']

ERR_INVALID_DB_PARAMETER_GROUP_STATE = "InvalidDBParameterGroupState"

def _default_engine_version_and_family(rds, engine: str) -> tuple[str, str]:
    """``(EngineVersion, DBParameterGroupFamily)`` of the current default version for *engine*.

    Returned as a PAIR, deliberately. A family derived apart from a pinned ``EngineVersion``
    drifts when AWS moves its default version, and CreateDBInstance then fails
    InvalidParameterCombination ("parameter group ... with DBParameterGroupFamily ... can't be
    used for this instance") before the check reaches the behaviour it exists to grade.
    Deriving both from the same call means the two can never drift apart, and the check
    tracks whatever AWS's default happens to be rather than encoding a version that expires.
    """
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    v = versions[0]
    return v["EngineVersion"], v["DBParameterGroupFamily"]

def _wait_available(rds, inst_id, timeout_s=900) -> None:
    """Poll until a DB instance reaches 'available'."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
        if status == "available":
            return
        time.sleep(2)
    raise AssertionError(f"DB instance {inst_id} available not met within {timeout_s}s")


def _wait_instance_gone(rds, inst_id, timeout_s=900) -> None:
    """Poll until DescribeDBInstances(inst_id) itself raises DBInstanceNotFound."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=inst_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"DB instance {inst_id} not-found not met within {timeout_s}s")


def _client_error(fn) -> tuple[str | None, str | None]:
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection but the call succeeded: {result!r}")


def _quietly(fn, not_found_code) -> None:
    """Teardown call that tolerates the resource already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != not_found_code:
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBParameterGroup while attached to a live instance rejects with
    InvalidDBParameterGroupState (over-permissiveness guard), the group survives the rejected
    call, and once the attaching instance is gone the identical delete succeeds.
    """
    rds = ctx.client("rds")
    engine_version, pg_family = _default_engine_version_and_family(rds, "mysql")

    # Positive control: DeleteDBParameterGroup on an unattached group of the same family
    # succeeds outright, so a later rejection cannot be mistaken for "delete never works here".
    control_pg_name = ctx.unique_name("sim2real-behav-pg-control-")
    rds.create_db_parameter_group(
        DBParameterGroupName=control_pg_name,
        DBParameterGroupFamily=pg_family,
        Description="sim2real behavioral check control",
    )
    rds.delete_db_parameter_group(DBParameterGroupName=control_pg_name)
    control_code, control_msg = _client_error(
        lambda: rds.describe_db_parameter_groups(DBParameterGroupName=control_pg_name)
    )
    assert control_code == "DBParameterGroupNotFound", (
        f"control group should be gone after an unblocked delete, got {control_code!r}"
    )
    assert control_msg == f"DBParameterGroup not found: {control_pg_name}", control_msg

    pg_name = ctx.unique_name("sim2real-behav-pg-inuse-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily=pg_family,
        Description="sim2real behavioral check",
    )
    # Instance is deleted first (LIFO), then the parameter group.
    ctx.on_cleanup(lambda: _quietly(
        lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name),
        "DBParameterGroupNotFound"))

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine="mysql",
        EngineVersion=engine_version,
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        BackupRetentionPeriod=0,
        DBParameterGroupName=pg_name,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _quietly(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True),
        "DBInstanceNotFound"))
    _wait_available(rds, inst_id)

    code, msg = _client_error(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))
    assert code == ERR_INVALID_DB_PARAMETER_GROUP_STATE, f"unexpected error code: {code!r}"
    assert msg == (
        f"One or more database instances are still members of this parameter group {pg_name}, "
        "so the group cannot be deleted"
    ), msg

    # Effect absent: an independent read shows the rejected call left the group untouched.
    described = rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)["DBParameterGroups"]
    assert len(described) == 1, f"parameter group should survive a rejected delete, got {described!r}"

    # Restore: remove the attaching instance, then the identical delete call now succeeds.
    rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
    _wait_instance_gone(rds, inst_id)

    rds.delete_db_parameter_group(DBParameterGroupName=pg_name)
    restored_code, restored_msg = _client_error(
        lambda: rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)
    )
    assert restored_code == "DBParameterGroupNotFound", (
        f"parameter group should be gone once its attaching instance is deleted, got {restored_code!r}"
    )
    assert restored_msg == f"DBParameterGroup not found: {pg_name}", restored_msg


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
