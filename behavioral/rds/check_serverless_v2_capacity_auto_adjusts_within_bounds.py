"""serverless-v2-capacity-auto-adjusts-within-bounds."""
from __future__ import annotations

import datetime
import secrets
import time

from botocore.exceptions import ClientError
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "serverless-v2-capacity-auto-adjusts-within-bounds"
GROUP = "server-side"
SERVICES = ["rds"]


# timing:real-time — metric: 300 s
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "concern:representation", "plane:control",
      "timing:real-time")
def run(ctx) -> None:
    """An Aurora Serverless v2 cluster's ServerlessDatabaseCapacity metric stays within its
    configured Min/MaxCapacity, before and after ModifyDBCluster raises both bounds; the check
    never sets capacity itself."""
    rds = ctx.client("rds")
    cw = ctx.client("cloudwatch")

    cluster_id = ctx.unique_name("sim2real-rds-sv2-")
    instance_id = ctx.unique_name("sim2real-rds-sv2i-")
    password = _rds_password()
    resource_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2rtest",
        MasterUserPassword=password,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1.0},
        Tags=resource_tags,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.serverless",
        Engine="aurora-postgresql",
        DBClusterIdentifier=cluster_id,
        Tags=resource_tags,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )

    _wait_for_instance_status(rds, instance_id, "available", timeout_s=1500)
    cluster = _wait_for_cluster_status(rds, cluster_id, "available", timeout_s=600)
    scaling = cluster["ServerlessV2ScalingConfiguration"]
    assert scaling["MinCapacity"] == 0.5 and scaling["MaxCapacity"] == 1.0, (
        f"expected initial ServerlessV2ScalingConfiguration {{0.5, 1.0}}, got {scaling}"
    )

    capacity = _poll_capacity_metric(cw, cluster_id, timeout_s=900)
    assert 0.5 <= capacity <= 1.0, f"observed ACU capacity {capacity} outside configured [0.5, 1.0] bounds"

    # Raise both bounds; the service must re-settle capacity at/above the new floor on its own.
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id,
        ServerlessV2ScalingConfiguration={"MinCapacity": 1.0, "MaxCapacity": 2.0},
        ApplyImmediately=True,
    )
    cluster = _wait_for_cluster_status(rds, cluster_id, "available", timeout_s=600)
    scaling = cluster["ServerlessV2ScalingConfiguration"]
    assert scaling["MinCapacity"] == 1.0 and scaling["MaxCapacity"] == 2.0, (
        f"expected raised ServerlessV2ScalingConfiguration {{1.0, 2.0}}, got {scaling}"
    )

    capacity_after = _poll_capacity_metric(
        cw, cluster_id, timeout_s=1200, min_timestamp=datetime.datetime.now(datetime.timezone.utc)
    )
    assert 1.0 <= capacity_after <= 2.0, (
        f"observed ACU capacity {capacity_after} did not respect the raised [1.0, 2.0] bounds"
    )



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


def _wait_for_cluster_status(rds: Any, cluster_id: str, status: str, *, timeout_s: float) -> dict:
    def _probe() -> dict:
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    result = _poll_until(
        _probe, lambda c: c["Status"] == status, timeout_s=timeout_s, interval_s=15
    )
    if result["Status"] != status:
        raise AssertionError(
            f"cluster {cluster_id} never reached status {status!r} (last: {result['Status']!r})"
        )
    return result


def _poll_capacity_metric(
    cw: Any,
    cluster_id: str,
    *,
    timeout_s: float,
    min_timestamp: "datetime.datetime | None" = None,
) -> float:
    """Return the latest ServerlessDatabaseCapacity datapoint, raising if none arrives in budget.
    RDS metric ingestion takes a few minutes with no hard SLA; absence is still a failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        end = datetime.datetime.now(datetime.timezone.utc)
        start = end - datetime.timedelta(minutes=30)
        resp = cw.get_metric_statistics(
            Namespace="AWS/RDS",
            MetricName="ServerlessDatabaseCapacity",
            Dimensions=[{"Name": "DBClusterIdentifier", "Value": cluster_id}],
            StartTime=start,
            EndTime=end,
            Period=300,
            Statistics=["Average"],
        )
        points = resp.get("Datapoints", [])
        if min_timestamp is not None:
            points = [p for p in points if p["Timestamp"] >= min_timestamp]
        if points:
            points.sort(key=lambda p: p["Timestamp"])
            return points[-1]["Average"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no ServerlessDatabaseCapacity datapoint for cluster {cluster_id} landed in "
                f"CloudWatch within {timeout_s}s -- ingestion latency exceeded budget"
            )
        time.sleep(30)


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
