"""slow-log-delivery-to-missing-log-group-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "slow-log-delivery-to-missing-log-group-rejected"
GROUP = "negative-classes"
SERVICES = ["elasticache", "logs"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A cache cluster accepts a slow-log delivery naming any CloudWatch Logs group up front;
    one naming a group that exists settles to an active delivery, while one naming a group
    that does not settles to an error naming it, and that group is never created."""
    ec = ctx.client("elasticache")
    logs = ctx.client("logs")

    present = ctx.unique_name("/sim2real/ec-slowlog-")
    logs.create_log_group(logGroupName=present)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=present))
    found = logs.describe_log_groups(logGroupNamePrefix=present)["logGroups"]
    assert [g["logGroupName"] for g in found] == [present], (
        f"expected the created log group {present!r} to be listed, got {found!r}"
    )

    subnet_group = _cache_subnet_group(ctx, ec)
    sg_id = ctx.network().security_group_id

    # Positive control: an identical request naming the log group that exists settles to an
    # active delivery. Without this, "a missing destination settles to an error" is
    # indistinguishable from "every slow-log delivery settles to an error".
    cluster_id_ok = ctx.unique_name("sim2real-ecspos-")[:40].rstrip("-")
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(ec, cluster_id_ok))
    _create_with_slowlog(ec, cluster_id_ok, subnet_group, sg_id, present)
    ok_cfg = _await_slowlog_settled(ec, cluster_id_ok)
    assert ok_cfg is not None and ok_cfg.get("Status") == "active", (
        f"expected the slow-log delivery naming the existing log group {present!r} to settle to "
        f"Status='active', got {ok_cfg!r}"
    )

    missing = ctx.unique_name("/sim2real/ec-slowlog-missing-")
    cluster_id = ctx.unique_name("sim2real-ecsl-")[:40].rstrip("-")
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(ec, cluster_id))
    _create_with_slowlog(ec, cluster_id, subnet_group, sg_id, missing)
    bad_cfg = _await_slowlog_settled(ec, cluster_id)
    assert bad_cfg is not None and bad_cfg.get("Status") == "error", (
        f"expected the slow-log delivery naming the missing log group {missing!r} to settle to "
        f"Status='error', got {bad_cfg!r}"
    )
    expected_message = f"Destination log group {missing} does not exist."
    assert bad_cfg.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {bad_cfg.get('Message')!r}"
    )

    groups = logs.describe_log_groups(logGroupNamePrefix=missing)["logGroups"]
    assert groups == [], (
        f"expected ElastiCache to never create the destination it could not find; "
        f"DescribeLogGroups on {missing!r} now returns {groups!r}"
    )


def _create_with_slowlog(ec, cluster_id: str, subnet_group: str, sg_id: str, log_group: str) -> dict:
    """CreateCacheCluster with slow-log delivery to `log_group`; returns the CacheCluster."""
    created = ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t4g.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
        SecurityGroupIds=[sg_id],
        LogDeliveryConfigurations=[
            {
                "LogType": "slow-log",
                "DestinationType": "cloudwatch-logs",
                "DestinationDetails": {"CloudWatchLogsDetails": {"LogGroup": log_group}},
                "LogFormat": "json",
            }
        ],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["CacheCluster"]
    assert created["CacheClusterId"] == cluster_id, (
        f"expected CreateCacheCluster to echo CacheClusterId {cluster_id!r}, got "
        f"{created.get('CacheClusterId')!r}"
    )
    return created


def _slowlog_cfg(ec, cluster_id: str) -> dict | None:
    items = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"]
    if not items:
        return None
    for cfg in items[0].get("LogDeliveryConfigurations") or []:
        if cfg.get("LogType") == "slow-log":
            return cfg
    return None


def _await_slowlog_settled(ec, cluster_id: str, timeout_s: float = 600.0, interval_s: float = 15.0):
    """The cluster's slow-log config once it leaves enabling/modifying, or the last-seen config
    (possibly still transitional) once the bounded wait expires; the caller grades the result."""
    deadline = time.monotonic() + timeout_s
    cfg = _slowlog_cfg(ec, cluster_id)
    while cfg is None or cfg.get("Status") in ("enabling", "modifying"):
        if time.monotonic() >= deadline:
            return cfg
        time.sleep(interval_s)
        cfg = _slowlog_cfg(ec, cluster_id)
    return cfg


def _cache_subnet_group(ctx, ec) -> str:
    """A cache subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-ec-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, name))
    return name


def _delete_subnet_group(ec, name, timeout_s=1500.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "CacheSubnetGroupNotFoundFault":
                return
            if code != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(15)


def _delete_cluster_when_settled(ec, cluster_id, timeout_s=1800.0) -> None:
    """Delete a cluster once it leaves its transitional state; a no-op if it was never created."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_cluster(CacheClusterId=cluster_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "CacheClusterNotFound":
                return
            if code != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                raise
        time.sleep(20)
    while time.monotonic() < deadline:
        try:
            ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "CacheClusterNotFound":
                return
            raise
        time.sleep(20)
    raise AssertionError(f"cache cluster {cluster_id} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
