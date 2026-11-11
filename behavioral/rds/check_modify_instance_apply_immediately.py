"""modify-instance-apply-immediately."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-apply-immediately"
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

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBInstance with ApplyImmediately=True applies BackupRetentionPeriod=3 without waiting
    for a maintenance window, as DescribeDBInstances reads back."""
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
        BackupRetentionPeriod=1,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))
    _wait_available(rds, inst_id)

    rds.modify_db_instance(
        DBInstanceIdentifier=inst_id, BackupRetentionPeriod=3, ApplyImmediately=True
    )

    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        inst = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
        if inst.get("DBInstanceStatus") == "available" and inst.get("BackupRetentionPeriod") == 3:
            break
        time.sleep(5)
    else:
        raise AssertionError(f"instance {inst_id} backup retention not applied in time")
    assert inst["BackupRetentionPeriod"] == 3, (
        f"backup retention not applied: {inst.get('BackupRetentionPeriod')}"
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
