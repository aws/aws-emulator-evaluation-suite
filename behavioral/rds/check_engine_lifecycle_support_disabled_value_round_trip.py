"""engine-lifecycle-support-disabled-value-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "engine-lifecycle-support-disabled-value-round-trip"
GROUP = "representation"
SERVICES = ["rds"]

_USER = "sim2real"
_PASS = "Sim2Real#Pass99"
_CLASS = "db.t3.micro"
_DISABLED = "open-source-rds-extended-support-disabled"
_ENABLED = "open-source-rds-extended-support"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _delete_instance(rds, inst_id):
    """Delete a DB instance, retrying while it is still 'creating' and so cannot be deleted yet."""
    deadline = time.monotonic() + 1700
    while True:
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBInstanceNotFound":
                return
            if code != "InvalidDBInstanceState" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _delete_cluster(rds, cluster_id):
    """Delete a DB cluster, retrying while it is still 'creating' and so cannot be deleted yet."""
    deadline = time.monotonic() + 1700
    while True:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBClusterNotFoundFault":
                return
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _default_engine_version(rds, engine):
    try:
        versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
            "DBEngineVersions", [])
    except ClientError:
        return None
    return versions[0]["EngineVersion"] if versions else None


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1700.0, interval_s=15.0):
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance and CreateDBCluster echo an explicit EngineLifecycleSupport of
    open-source-rds-extended-support-disabled on DescribeDBInstances/DescribeDBClusters, and
    default to open-source-rds-extended-support when the member is omitted.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/extended-support-viewing.html
    """
    rds = ctx.client("rds")
    subnet_group = _network_db_subnet_group(ctx, rds)
    pg_version = _default_engine_version(rds, "postgres")
    aurora_version = _default_engine_version(rds, "aurora-postgresql")

    inst_disabled_id = ctx.unique_name("sim2real-behav-inst-dis-")
    inst_kwargs = dict(
        DBInstanceIdentifier=inst_disabled_id, Engine="postgres", DBInstanceClass=_CLASS,
        AllocatedStorage=20, MasterUsername=_USER, MasterUserPassword=_PASS,
        BackupRetentionPeriod=0, DeletionProtection=False, Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group, EngineLifecycleSupport=_DISABLED,
    )
    if pg_version:
        inst_kwargs["EngineVersion"] = pg_version
    rds.create_db_instance(**inst_kwargs)
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_disabled_id))

    inst_default_id = ctx.unique_name("sim2real-behav-inst-def-")
    inst_kwargs = dict(
        DBInstanceIdentifier=inst_default_id, Engine="postgres", DBInstanceClass=_CLASS,
        AllocatedStorage=20, MasterUsername=_USER, MasterUserPassword=_PASS,
        BackupRetentionPeriod=0, DeletionProtection=False, Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    if pg_version:
        inst_kwargs["EngineVersion"] = pg_version
    rds.create_db_instance(**inst_kwargs)
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_default_id))

    clu_disabled_id = ctx.unique_name("sim2real-behav-clu-dis-")
    clu_kwargs = dict(
        DBClusterIdentifier=clu_disabled_id, Engine="aurora-postgresql",
        MasterUsername=_USER, MasterUserPassword=_PASS,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False, Tags=_MANAGED_TAGS, DBSubnetGroupName=subnet_group,
        EngineLifecycleSupport=_DISABLED,
    )
    if aurora_version:
        clu_kwargs["EngineVersion"] = aurora_version
    rds.create_db_cluster(**clu_kwargs)
    ctx.on_cleanup(lambda: _delete_cluster(rds, clu_disabled_id))

    clu_default_id = ctx.unique_name("sim2real-behav-clu-def-")
    clu_kwargs = dict(
        DBClusterIdentifier=clu_default_id, Engine="aurora-postgresql",
        MasterUsername=_USER, MasterUserPassword=_PASS,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False, Tags=_MANAGED_TAGS, DBSubnetGroupName=subnet_group,
    )
    if aurora_version:
        clu_kwargs["EngineVersion"] = aurora_version
    rds.create_db_cluster(**clu_kwargs)
    ctx.on_cleanup(lambda: _delete_cluster(rds, clu_default_id))

    inst_disabled = rds.describe_db_instances(DBInstanceIdentifier=inst_disabled_id)["DBInstances"][0]
    assert inst_disabled["EngineLifecycleSupport"] == _DISABLED, (
        f"an explicit EngineLifecycleSupport={_DISABLED!r} on CreateDBInstance must be echoed by "
        f"DescribeDBInstances; got {inst_disabled['EngineLifecycleSupport']!r}")

    inst_default = rds.describe_db_instances(DBInstanceIdentifier=inst_default_id)["DBInstances"][0]
    assert inst_default["EngineLifecycleSupport"] == _ENABLED, (
        f"CreateDBInstance with EngineLifecycleSupport omitted must default to {_ENABLED!r}; "
        f"DescribeDBInstances shows {inst_default['EngineLifecycleSupport']!r}")

    clu_disabled = rds.describe_db_clusters(DBClusterIdentifier=clu_disabled_id)["DBClusters"][0]
    assert clu_disabled["EngineLifecycleSupport"] == _DISABLED, (
        f"an explicit EngineLifecycleSupport={_DISABLED!r} on CreateDBCluster must be echoed by "
        f"DescribeDBClusters; got {clu_disabled['EngineLifecycleSupport']!r}")

    clu_default = rds.describe_db_clusters(DBClusterIdentifier=clu_default_id)["DBClusters"][0]
    assert clu_default["EngineLifecycleSupport"] == _ENABLED, (
        f"CreateDBCluster with EngineLifecycleSupport omitted must default to {_ENABLED!r}; "
        f"DescribeDBClusters shows {clu_default['EngineLifecycleSupport']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
