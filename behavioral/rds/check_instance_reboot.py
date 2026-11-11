"""instance-reboot."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-reboot"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

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


def _wait_for_status(rds, inst_id, target_status, *, timeout_s, interval_s) -> bool:
    """Poll tightly for `target_status` to appear at least once. Returns False (never
    raises) if the deadline passes without ever observing it -- absence is the caller's
    assertion to make, not this helper's."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
        if status == target_status:
            return True
        time.sleep(interval_s)
    return False

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RebootDBInstance moves the instance to an observed 'rebooting' state and back to
    'available', so a target that ignores the reboot fails."""
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
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))
    _wait_available(rds, inst_id)

    rds.reboot_db_instance(DBInstanceIdentifier=inst_id)
    seen_rebooting = _wait_for_status(rds, inst_id, "rebooting", timeout_s=120, interval_s=2)
    assert seen_rebooting, (
        f"RebootDBInstance on {inst_id} never surfaced status 'rebooting' within 120s "
        "-- the call must actually change observable state, not act as a no-op"
    )

    _wait_available(rds, inst_id)
    final = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    assert final["DBInstanceStatus"] == "available", (
        f"expected DB instance {inst_id} status 'available' after reboot completed, "
        f"got {final['DBInstanceStatus']!r}"
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
