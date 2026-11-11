"""maintenance-window-controls-pending-change-application."""
from __future__ import annotations

import datetime
import secrets
import time

from botocore.exceptions import ClientError
from typing import Any, Callable

from behavioral_harness import tags


CHECK = "maintenance-window-controls-pending-change-application"
GROUP = "server-side"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBInstance(AllocatedStorage=30, ApplyImmediately=False) keeps the live AllocatedStorage at 20 and
    shows 30 only in PendingModifiedValues throughout a bounded poll, with the preferred maintenance
    window set three days ahead so it cannot open during the check."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-mw-")
    password = _rds_password()

    # A maintenance window 3 days ahead, at a fixed 30-minute slot: it recurs weekly, so its next
    # occurrence falls well outside this check's runtime.
    future_day = (datetime.datetime.utcnow() + datetime.timedelta(days=3)).strftime("%a").lower()
    maintenance_window = f"{future_day}:04:00-{future_day}:04:30"

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="s2rtest",
        MasterUserPassword=password,
        AllocatedStorage=20,
        StorageType="gp2",
        PubliclyAccessible=False,
        PreferredMaintenanceWindow=maintenance_window,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
        )
    )

    _wait_for_instance_status(rds, instance_id, "available", timeout_s=1200)

    before = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert before["AllocatedStorage"] == 20, f"expected precondition AllocatedStorage=20, got {before['AllocatedStorage']!r}"
    assert before["PreferredMaintenanceWindow"].lower() == maintenance_window, (
        f"expected PreferredMaintenanceWindow={maintenance_window!r}, "
        f"got {before['PreferredMaintenanceWindow']!r}"
    )

    rds.modify_db_instance(
        DBInstanceIdentifier=instance_id,
        AllocatedStorage=30,
        ApplyImmediately=False,
    )

    # Immediately after the call: the requested value must show up as PENDING, not live.
    after_modify = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert after_modify["AllocatedStorage"] == 20, "storage changed live despite ApplyImmediately=False"
    pending = after_modify.get("PendingModifiedValues", {})
    assert pending.get("AllocatedStorage") == 30, f"expected pending AllocatedStorage=30, got {pending!r}"

    # Poll for a bounded window: the pending change must NOT self-apply outside the declared
    # maintenance window (which is several days away).
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        assert instance["AllocatedStorage"] == 20, (
            "AllocatedStorage applied itself outside the preferred maintenance window"
        )
        assert instance.get("PendingModifiedValues", {}).get("AllocatedStorage") == 30, (
            "pending AllocatedStorage change disappeared without being applied"
        )
        time.sleep(2)


def _rds_password() -> str:
    return "S2r" + secrets.token_hex(8)


def _wait_for_instance_status(rds: Any, instance_id: str, status: str, *, timeout_s: float) -> dict:
    def _probe() -> dict:
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    result = _poll_until(
        _probe, lambda inst: inst["DBInstanceStatus"] == status, timeout_s=timeout_s, interval_s=15
    )
    if result["DBInstanceStatus"] != status:
        raise AssertionError(
            f"instance {instance_id} never reached status {status!r} "
            f"(last: {result['DBInstanceStatus']!r})"
        )
    return result


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


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
