"""create-duplicate-instance."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "create-duplicate-instance"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

ERR_DB_INSTANCE_ALREADY_EXISTS = "DBInstanceAlreadyExists"
ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"

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


def _wait_deleted(rds, inst_id, timeout_s=900) -> None:
    """Poll until describe_db_instances raises DBInstanceNotFound."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=inst_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == ERR_DB_INSTANCE_NOT_FOUND:
                return
            raise
        time.sleep(2)
    raise AssertionError(f"DB instance {inst_id} not deleted within {timeout_s}s")


def _error_code(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance with an identifier already in use is rejected with DBInstanceAlreadyExists and
    leaves the original instance unchanged; once the original is deleted, the identifier is gone."""
    rds = ctx.client("rds")
    inst_id = ctx.unique_name("sim2real-behav-inst-")
    kwargs = dict(
        DBInstanceIdentifier=inst_id,
        Engine="mysql",
        EngineVersion="8.0",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
    )
    rds.create_db_instance(**kwargs)

    def _cleanup() -> None:
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != ERR_DB_INSTANCE_NOT_FOUND:
                raise

    ctx.on_cleanup(_cleanup)
    _wait_available(rds, inst_id)

    # The duplicate attempt uses a DIFFERENT AllocatedStorage than the original,
    # so the independent read below cannot pass by coincidence: a target that
    # silently accepted this as an implicit update instead of rejecting it would
    # show the storage size having drifted.
    dup_kwargs = dict(kwargs, AllocatedStorage=25)
    code, message = _error_code(lambda: rds.create_db_instance(**dup_kwargs))
    assert code == ERR_DB_INSTANCE_ALREADY_EXISTS, f"unexpected error code: {code!r}"
    assert message == "DB instance already exists", message

    # Effect absent: an independent read, through a different operation than
    # either create call, shows the original instance -- exactly one of it --
    # untouched by the rejected duplicate.
    matches = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"]
    assert len(matches) == 1, f"expected exactly 1 instance for {inst_id!r}, found {len(matches)}"
    desc = matches[0]
    assert desc["AllocatedStorage"] == 20, (
        f"rejected duplicate must not alter storage: expected 20, got {desc['AllocatedStorage']}"
    )
    assert desc["DBInstanceStatus"] == "available", (
        f"rejected duplicate must not disturb instance state: got {desc['DBInstanceStatus']!r}"
    )

    # The identifier is only live as long as the instance is: delete it and
    # prove -- via an independent read, and via a second, distinct mutating
    # operation -- that it is now gone, not merely refused a duplicate.
    rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
    _wait_deleted(rds, inst_id)

    gone_code, gone_message = _error_code(lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id))
    assert gone_code == ERR_DB_INSTANCE_NOT_FOUND, (
        f"deleted instance {inst_id!r} should not exist, got {gone_code!r}"
    )
    assert gone_message == f"DBInstance {inst_id} not found.", gone_message
    reboot_code, reboot_message = _error_code(lambda: rds.reboot_db_instance(DBInstanceIdentifier=inst_id))
    assert reboot_code == ERR_DB_INSTANCE_NOT_FOUND, (
        f"a mutation on the deleted identifier {inst_id!r} should also fail, got {reboot_code!r}"
    )
    assert reboot_message == f"DBInstance not found: {inst_id}", reboot_message


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
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
