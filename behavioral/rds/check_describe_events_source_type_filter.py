"""describe-events-source-type-filter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-events-source-type-filter"
GROUP = 'events'
SERVICES = ['rds']


def _postgres_instance_version(ctx) -> str:
    """A widely-orderable postgres engine version (default), else a safe fallback."""
    rds = ctx.client("rds")
    try:
        versions = rds.describe_db_engine_versions(
            Engine="postgres", DefaultOnly=True
        ).get("DBEngineVersions", [])
    except ClientError:
        versions = []
    return (versions[0]["EngineVersion"] if versions else None) or "16.4"


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEvents' SourceType filter actually discriminates by source type: a genuine
    db-instance event is visible when filtered by SourceType='db-instance', and does not leak
    into a same-window query filtered by an unrelated SourceType.
    """
    rds = ctx.client("rds")
    inst_id = ctx.unique_name("sim2real-behav-inst-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine="postgres",
        EngineVersion=_postgres_instance_version(ctx),
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        BackupRetentionPeriod=0,
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))
    _wait_available(rds, inst_id)

    matching = rds.describe_events(
        SourceIdentifier=inst_id, SourceType="db-instance", Duration=180
    )["Events"]
    assert matching, f"expected at least one db-instance event for {inst_id}, got none"
    for event in matching:
        assert event["SourceType"] == "db-instance", (
            f"expected SourceType db-instance, got {event.get('SourceType')!r}"
        )
        assert event["SourceIdentifier"] == inst_id, (
            f"expected SourceIdentifier {inst_id!r}, got {event.get('SourceIdentifier')!r}"
        )

    unrelated = rds.describe_events(SourceType="db-parameter-group", Duration=180)["Events"]
    leaked = [e for e in unrelated if e.get("SourceIdentifier") == inst_id]
    assert not leaked, (
        f"SourceType=db-parameter-group query leaked db-instance event(s) for {inst_id}: {leaked}"
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
