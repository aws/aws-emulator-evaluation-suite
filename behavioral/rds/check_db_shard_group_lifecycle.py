"""db-shard-group-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "db-shard-group-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]

_ADMIN_PW = "Sim2RealBehav1"
_TAGS = [{"Key": "sim2real", "Value": "true"}]
_UNSUPPORTED_CODES = {
    "InvalidParameterValue",
    "InvalidParameterCombination",
    "UnsupportedDBEngineVersionFault",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB shard group on an Aurora Limitless cluster becomes available, ModifyDBShardGroup sets
    MaxACU to 64, a reboot returns it to available, and DeleteDBShardGroup removes it."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")
    subnet_group = _create_subnet_group(ctx)

    engine_version = _pick_limitless_engine_version(rds)
    if engine_version is None:
        raise AssertionError("no aurora-postgresql *-limitless engine version available in this region")

    monitoring_role_arn = _create_monitoring_role(ctx, iam)

    cluster_id = ctx.unique_name("sim2real-behav-cl-")
    try:
        _create_cluster_with_role_retry(
            rds,
            ctx=ctx,
            timeout_s=_budget_s(ctx, 120.0),
            DBClusterIdentifier=cluster_id,
            Engine="aurora-postgresql",
            EngineVersion=engine_version,
            MasterUsername="simadmin",
            MasterUserPassword=_ADMIN_PW,
            DBSubnetGroupName=subnet_group,
            ClusterScalabilityType="limitless",
            StorageType="aurora-iopt1",
            EnablePerformanceInsights=True,
            MonitoringInterval=5,
            MonitoringRoleArn=monitoring_role_arn,
            EnableCloudwatchLogsExports=["postgresql"],
            Tags=_TAGS,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] in _UNSUPPORTED_CODES:
            raise AssertionError(f"Aurora Limitless Database not available in this account/region/version: {e}")
        raise
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))
    _wait_cluster_status(ctx, cluster_id, {"available"}, timeout_s=1800.0)

    shard_group_id = ctx.unique_name("sim2real-behav-sg-")
    rds.create_db_shard_group(
        DBShardGroupIdentifier=shard_group_id,
        DBClusterIdentifier=cluster_id,
        MaxACU=32.0,
        ComputeRedundancy=0,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_delete_shard_group(ctx, shard_group_id))
    _wait_shard_group_status(ctx, shard_group_id, {"available"}, timeout_s=1800.0)

    _retry_while_cluster_settling(
        lambda: rds.modify_db_shard_group(DBShardGroupIdentifier=shard_group_id, MaxACU=64.0),
        timeout_s=_budget_s(ctx, 900.0), ctx=ctx,
    )
    sg = _wait_shard_group_status(ctx, shard_group_id, {"available"}, timeout_s=900.0)
    assert sg["MaxACU"] == 64.0, f"expected MaxACU=64.0, got {sg['MaxACU']!r}"

    rebooting = _retry_while_cluster_settling(
        lambda: rds.reboot_db_shard_group(DBShardGroupIdentifier=shard_group_id),
        timeout_s=_budget_s(ctx, 900.0), ctx=ctx,
    )
    assert rebooting["Status"] in ("available", "rebooting"), (
        f"unexpected status in the reboot_db_shard_group response: {rebooting['Status']!r}"
    )
    _wait_shard_group_status(ctx, shard_group_id, {"available"}, timeout_s=900.0)

    _retry_while_cluster_settling(
        lambda: rds.delete_db_shard_group(DBShardGroupIdentifier=shard_group_id),
        timeout_s=_budget_s(ctx, 900.0), ctx=ctx,
    )
    _wait_shard_group_gone(ctx, shard_group_id, timeout_s=_budget_s(ctx, 1800.0), capped=True)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _safe_delete_shard_group(ctx, shard_group_id: str) -> None:
    """Teardown: delete the shard group (retrying while the cluster settles) and wait it out."""
    rds = ctx.client("rds")

    def _delete():
        try:
            rds.delete_db_shard_group(DBShardGroupIdentifier=shard_group_id)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("DBShardGroupNotFound", "InvalidDBShardGroupState"):
                raise

    _retry_while_cluster_settling(_delete)
    _wait_shard_group_gone(ctx, shard_group_id)


def _delete_cluster(ctx, cluster_id: str, timeout_s: float = 1800.0) -> None:
    """Teardown: delete the cluster and wait until it is gone so its subnet group can be removed."""
    rds = ctx.client("rds")

    def _delete():
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        except ClientError as e:
            if e.response["Error"]["Code"] != "DBClusterNotFoundFault":
                raise

    _retry_while_cluster_settling(_delete)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"DB cluster {cluster_id} still visible {timeout_s}s after delete")


def _create_cluster_with_role_retry(rds, *, ctx, timeout_s: float = 120.0, poll_s: float = 2.0, **kwargs) -> None:
    """MonitoringRoleArn names a role created moments ago and IAM propagation to RDS is
    eventually consistent, so CreateDBCluster is retried on InvalidParameterValue, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.create_db_cluster(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterValue" or time.monotonic() >= deadline:
                if e.response["Error"]["Code"] == "InvalidParameterValue" and _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateDBCluster monitoring role propagation: the run budget ended first; not graded"
                    ) from e
                raise
            time.sleep(poll_s)


def _retry_while_cluster_settling(fn, *, timeout_s: float = 900.0, interval_s: float = 2.0, ctx=None):
    """A DB shard group operation transiently rejects with InvalidDBClusterStateFault while the
    parent cluster is still settling after the shard group's own last state change; bounded-retry,
    not one shot."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidDBClusterStateFault":
                raise
            last_exc = e
            time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("shard group operation while the cluster settles: the run budget ended first; not graded")
    raise AssertionError(f"operation never became valid within {timeout_s}s: {last_exc}")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=2.0, ctx):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("cluster/shard group status: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _own_subnet_ids(ctx, count: int = 3) -> list[str]:
    """Subnets in up to `count` AZs of a VPC this check creates; all registered for cleanup."""
    ec2 = ctx.client("ec2")
    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required"]}]
        )["AvailabilityZones"]
        if z["State"] == "available"
    )[:count]
    assert len(azs) >= 2, "need at least 2 AZs to create a DB subnet group"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.82.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.82.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _drop_subnet(ec2, sid))
        ids.append(sid)
    return ids


def _drop_subnet(ec2, subnet_id: str, timeout_s: float = 900.0) -> None:
    """Teardown: wait out the RDS ENIs left in the subnet, then delete it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        )["NetworkInterfaces"]
        if not enis:
            break
        time.sleep(2)
    _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id))


def _retry_dependency(fn, timeout_s: float = 600.0, delay: float = 2.0) -> None:
    """Run a teardown delete, retrying DependencyViolation until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(delay)


def _create_subnet_group(ctx) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=_own_subnet_ids(ctx),
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _pick_limitless_engine_version(rds) -> str | None:
    versions = rds.describe_db_engine_versions(Engine="aurora-postgresql")["DBEngineVersions"]
    limitless = [v["EngineVersion"] for v in versions if v["EngineVersion"].endswith("-limitless")]
    return sorted(limitless)[-1] if limitless else None


def _create_monitoring_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-sg-mon-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "monitoring.rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole",
        )
    )
    return arn


def _wait_cluster_status(ctx, cluster_id: str, statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 2.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    return _poll_until(probe, lambda c: c["Status"] in statuses, timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s,
                       ctx=ctx)


def _wait_shard_group_status(ctx, shard_group_id: str, statuses: set[str], timeout_s: float = 900.0, interval_s: float = 2.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_group_id)["DBShardGroups"][0]

    return _poll_until(probe, lambda s: s["Status"] in statuses, timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s,
                       ctx=ctx)


def _wait_shard_group_gone(ctx, shard_group_id: str, timeout_s: float = 1800.0, interval_s: float = 2.0,
                           capped: bool = False) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_group_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBShardGroupNotFound":
                return
            raise
        if not resp["DBShardGroups"]:
            return
        time.sleep(interval_s)
    if capped and _budget_spent(ctx):
        raise TimeoutError(f"shard group {shard_group_id} deleted: the run budget ended first; not graded")
    raise AssertionError(f"shard group {shard_group_id} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
