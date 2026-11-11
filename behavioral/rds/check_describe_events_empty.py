"""describe-events-empty."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-events-empty"
GROUP = 'events'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEvents for an instance identifier not yet created is empty, and once the instance
    exists the same query returns its creation events."""
    rds = ctx.client("rds")

    inst_id = ctx.unique_name("sim2real-behav-evinst-")

    def _events():
        return rds.describe_events(
            SourceType="db-instance",
            SourceIdentifier=inst_id,
            Duration=1440,
        )["Events"]

    before = _events()
    assert before == [], f"expected no events yet for not-yet-created {inst_id}, got {before!r}"

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
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
    )

    deadline = time.monotonic() + 900
    status = None
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0][
            "DBInstanceStatus"
        ]
        if status == "available":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"{inst_id} did not become available in time (last status={status!r})")

    deadline = time.monotonic() + 300
    after: list = []
    while time.monotonic() < deadline:
        after = _events()
        if after:
            break
        time.sleep(2)
    assert after, f"expected creation events for {inst_id} once available, got none within 300s"
    assert all(e.get("SourceIdentifier") == inst_id for e in after), after
    assert all(e.get("SourceType") == "db-instance" for e in after), after


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
