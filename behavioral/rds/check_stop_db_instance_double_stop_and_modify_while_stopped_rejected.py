"""stop-db-instance-double-stop-and-modify-while-stopped-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-db-instance-double-stop-and-modify-while-stopped-rejected"
GROUP = "instance_lifecycle"
SERVICES = ["rds"]

_USER = "sim2real"
_PASS = "Sim2Real#Pass99"
_NEW_PASS = "Sim2Real#Pass00"


def _error(fn) -> tuple[str, str]:
    """Invoke fn(); return the AWS (error code, message), or raise if it unexpectedly succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _describe(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_status(ctx: Any, rds: Any, db_id: str, status: str, *, timeout_s: float) -> dict[str, Any]:
    """Poll every 2 s until the instance reports status, within timeout_s capped by the run budget."""
    wait_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + wait_s
    inst = _describe(rds, db_id)
    while inst["DBInstanceStatus"] != status:
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"DB instance {db_id!r} status={status!r}: the run budget ended first; not graded"
                )
            raise AssertionError(
                f"DB instance {db_id!r} never reached status={status!r} within {wait_s:.0f}s; "
                f"last status={inst['DBInstanceStatus']!r}"
            )
        time.sleep(2)
        inst = _describe(rds, db_id)
    return inst


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFoundFault":
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A stopped DB instance rejects a second StopDBInstance and a ModifyDBInstance, stays stopped,
    and once started again is 'available' at the SAME endpoint address it had before."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-stopstart-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername=_USER,
        MasterUserPassword=_PASS,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        Tags=[
            {"Key": "sim2real", "Value": "stop-db-instance-double-stop-and-modify-while-stopped-rejected"}
        ],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))

    available = _wait_for_status(ctx, rds, db_id, "available", timeout_s=1200)
    endpoint_before = available["Endpoint"]["Address"]
    assert endpoint_before, f"instance {db_id!r} is 'available' but reports no endpoint address"

    rds.stop_db_instance(DBInstanceIdentifier=db_id)
    stopped = _wait_for_status(ctx, rds, db_id, "stopped", timeout_s=900)
    assert stopped["DBInstanceStatus"] == "stopped", stopped["DBInstanceStatus"]

    # Break exactly one thing at a time, both while genuinely stopped.
    stop_err = _error(lambda: rds.stop_db_instance(DBInstanceIdentifier=db_id))
    modify_err = _error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=db_id, MasterUserPassword=_NEW_PASS, ApplyImmediately=True
        )
    )
    expected_stop = ("InvalidDBInstanceState", f"Instance {db_id} is not in available state.")
    assert stop_err == expected_stop, (
        f"a second StopDBInstance on an already-stopped instance: expected {expected_stop!r}, "
        f"got {stop_err!r} (ModifyDBInstance answered {modify_err!r})"
    )
    expected_modify = (
        "InvalidDBInstanceState",
        "You can't modify a stopped DB instance. Start the DB instance, and then modify it.",
    )
    assert modify_err == expected_modify, (
        f"ModifyDBInstance on a stopped instance: expected {expected_modify!r}, got {modify_err!r}"
    )

    # Effect absent: still stopped after both rejections, not nudged into any other state.
    still_stopped = _describe(rds, db_id)
    assert still_stopped["DBInstanceStatus"] == "stopped", (
        f"instance {db_id!r} should remain 'stopped' after two rejected calls; got "
        f"{still_stopped['DBInstanceStatus']!r}"
    )

    rds.start_db_instance(DBInstanceIdentifier=db_id)
    restarted = _wait_for_status(ctx, rds, db_id, "available", timeout_s=1200)
    endpoint_after = restarted["Endpoint"]["Address"]
    assert endpoint_after == endpoint_before, (
        f"restarting a stopped instance must preserve its endpoint address: before={endpoint_before!r} "
        f"after={endpoint_after!r}"
    )


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=840.0, interval_s=15.0):
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
