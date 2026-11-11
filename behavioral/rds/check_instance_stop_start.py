"""instance-stop-start."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-stop-start"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

def _wait_available(rds, inst_id, timeout_s=900) -> None:
    """Poll until a DB instance reaches 'available'."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
        if status == "available":
            return
        time.sleep(2)
    raise AssertionError(
        f"DB instance {inst_id} expected status 'available' within {timeout_s}s, last: {status}"
    )

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopDBInstance takes an available DB instance to 'stopped' within 600 s.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_StopInstance.html"""
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

    rds.stop_db_instance(DBInstanceIdentifier=inst_id)
    deadline = time.monotonic() + 600
    status = "available"
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
        if status == "stopped":
            break
        time.sleep(2)
    assert status == "stopped", f"instance {inst_id} expected status 'stopped' within 600s, last: {status}"


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
