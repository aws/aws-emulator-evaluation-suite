"""delete-instance-deletion-protection."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "delete-instance-deletion-protection"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

ERR_INVALID_PARAMETER_COMBINATION = "InvalidParameterCombination"
ERR_INSTANCE_NOT_FOUND = "DBInstanceNotFound"


def _error_code(fn):
    """The AWS error code and message raised by fn(). Raises rather than returning a falsy sentinel
    when fn() unexpectedly SUCCEEDS."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be REJECTED but it succeeded, returning {resp!r}")


def _describe(rds, inst_id):
    """DescribeDBInstances for one id, or None once it no longer exists."""
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ERR_INSTANCE_NOT_FOUND:
            return None
        raise


def _wait_available(rds, inst_id, timeout_s=900) -> dict:
    """Poll until a DB instance reaches 'available'; return its describe payload."""
    deadline = time.monotonic() + timeout_s
    while True:
        inst = _describe(rds, inst_id)
        if inst is not None and inst["DBInstanceStatus"] == "available":
            return inst
        if time.monotonic() >= deadline:
            raise AssertionError(f"DB instance {inst_id} available not met within {timeout_s}s")
        time.sleep(2)


def _wait_deletion_protection(rds, inst_id, want, timeout_s=180) -> dict:
    """Poll until DeletionProtection reads `want`; return the describe payload."""
    deadline = time.monotonic() + timeout_s
    while True:
        inst = _describe(rds, inst_id)
        if inst is not None and inst.get("DeletionProtection") is want:
            return inst
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"DB instance {inst_id} DeletionProtection never reached {want}; "
                f"last observed {inst and inst.get('DeletionProtection')!r}"
            )
        time.sleep(2)


def _wait_gone(rds, inst_id, timeout_s=1200) -> None:
    """Poll until DescribeDBInstances reports the instance not found."""
    deadline = time.monotonic() + timeout_s
    while True:
        if _describe(rds, inst_id) is None:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"DB instance {inst_id} was never removed within {timeout_s}s")
        time.sleep(2)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBInstance on a DeletionProtection=True instance is rejected with InvalidParameterCombination
    and leaves it available and protected; after the flag is cleared, the same delete removes it."""
    rds = ctx.client("rds")
    inst_id = ctx.unique_name("sim2real-behav-inst-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine="mysql",
        EngineVersion="8.0",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        BackupRetentionPeriod=0,
        DeletionProtection=True,
        DBSubnetGroupName=subnet_group,
    )

    cleanup_state = {"deleted": False}

    # Safety net only: the check itself deletes the instance on the success path below. This
    # covers an early failure, and must disable DeletionProtection before deleting either way.
    def _cleanup():
        if cleanup_state["deleted"]:
            return
        try:
            rds.modify_db_instance(
                DBInstanceIdentifier=inst_id, DeletionProtection=False, ApplyImmediately=True
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "AuthorizationNotFound",
                "BackupPolicyNotFoundFault",
                "CertificateNotFound",
                "DBInstanceNotFound",
                "DBParameterGroupNotFound",
                "DBSecurityGroupNotFound",
                "DBSubnetGroupNotFoundFault",
                "DomainNotFoundFault",
                "OptionGroupNotFoundFault",
            ):
                raise
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DBInstanceNotFound":
                raise
    ctx.on_cleanup(_cleanup)
    _wait_available(rds, inst_id)

    # --- break exactly one thing: delete a protected instance.
    code, message = _error_code(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    )
    assert code == ERR_INVALID_PARAMETER_COMBINATION, f"unexpected error code: {code!r}"
    assert message == (
        "Cannot delete protected DB Instance, please disable deletion protection and try again."
    ), message

    # --- effect absent: an INDEPENDENT read shows the instance untouched by the refused call.
    still_there = _describe(rds, inst_id)
    assert still_there is not None, (
        f"the refused delete removed instance {inst_id} anyway -- DescribeDBInstances now "
        f"reports {ERR_INSTANCE_NOT_FOUND}"
    )
    assert still_there["DBInstanceStatus"] == "available", (
        f"the refused delete moved instance {inst_id} out of 'available': "
        f"{still_there['DBInstanceStatus']!r}"
    )
    assert still_there["DeletionProtection"] is True, (
        f"the refused delete cleared DeletionProtection on {inst_id} as a side effect"
    )

    # --- positive control: clear the one thing that was broken, and the SAME call must work.
    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id, DeletionProtection=False, ApplyImmediately=True
    )
    _wait_deletion_protection(rds, inst_id, False)

    rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    _wait_gone(rds, inst_id)
    cleanup_state["deleted"] = True

    final_code, final_message = _error_code(lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id))
    assert final_code == ERR_INSTANCE_NOT_FOUND, (
        f"instance {inst_id} must be unresolvable with {ERR_INSTANCE_NOT_FOUND} after deletion, "
        f"got {final_code!r}"
    )
    assert final_message == f"DBInstance {inst_id} not found.", final_message


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
