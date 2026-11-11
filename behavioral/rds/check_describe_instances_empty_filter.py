"""describe-instances-empty-filter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets


CHECK = "describe-instances-empty-filter"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBInstances with no identifier and no filters lists a newly created instance, and
    a filter naming only an unrelated identifier excludes it."""
    rds = ctx.client("rds")
    inst_id = ctx.unique_name("sim2real-behav-inst-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine="postgres",
        EngineVersion=_postgres_instance_version(ctx),
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        BackupRetentionPeriod=0,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))

    unfiltered = rds.describe_db_instances()
    unfiltered_ids = {i["DBInstanceIdentifier"] for i in unfiltered["DBInstances"]}
    assert inst_id in unfiltered_ids, (
        f"unfiltered DescribeDBInstances did not include {inst_id}: saw {sorted(unfiltered_ids)}"
    )

    ghost_id = ctx.unique_name("sim2real-behav-inst-")
    filtered = rds.describe_db_instances(
        Filters=[{"Name": "db-instance-id", "Values": [ghost_id]}]
    )
    filtered_ids = {i["DBInstanceIdentifier"] for i in filtered["DBInstances"]}
    assert inst_id not in filtered_ids, (
        f"Filters=[db-instance-id={ghost_id}] returned our real instance {inst_id}: "
        f"the filter is not restricting the result set"
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
