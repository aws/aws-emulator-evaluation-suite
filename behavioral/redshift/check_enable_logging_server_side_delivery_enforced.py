"""enable-logging-server-side-delivery-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets


CHECK = "enable-logging-server-side-delivery-enforced"
GROUP = "server-side"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a single EnableLogging call Redshift itself creates the CloudWatch Logs log groups for the
    exported log types, visible in DescribeLoggingStatus and DescribeLogGroups.
    """
    redshift = ctx.client("redshift")
    logs = ctx.client("logs")

    cluster_id = ctx.unique_name("sim2real-behav-log-").lower()
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        ClusterType="single-node",
        NodeType="ra3.xlplus",
        MasterUsername="sim2realadmin",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        DBName="sim2real",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=_network_redshift_subnet_group(ctx, redshift),
    )
    ctx.on_cleanup(
        lambda: _retry_while_held(lambda: redshift.delete_cluster(
            ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True
        ), "InvalidClusterState", timeout_s=600.0)
    )
    _wait_cluster_status(ctx, cluster_id, {"available"}, timeout_s=1200, interval_s=15)

    enable_resp = redshift.enable_logging(
        ClusterIdentifier=cluster_id,
        LogDestinationType="cloudwatch",
        LogExports=["connectionlog", "userlog"],
    )
    ctx.on_cleanup(lambda: redshift.disable_logging(ClusterIdentifier=cluster_id))

    assert enable_resp["LoggingEnabled"] is True, (
        f"expected LoggingEnabled=True from EnableLogging, got {enable_resp['LoggingEnabled']!r}"
    )
    assert enable_resp["LogDestinationType"] == "cloudwatch", (
        f"expected LogDestinationType=cloudwatch, got {enable_resp['LogDestinationType']!r}"
    )
    assert sorted(enable_resp["LogExports"]) == ["connectionlog", "userlog"], (
        f"expected LogExports=[connectionlog, userlog], got {sorted(enable_resp['LogExports'])!r}"
    )

    status = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
    assert status["LoggingEnabled"] is True, (
        f"expected DescribeLoggingStatus LoggingEnabled=True, got {status['LoggingEnabled']!r}"
    )
    assert status["LogDestinationType"] == "cloudwatch", (
        f"expected DescribeLoggingStatus LogDestinationType=cloudwatch, got {status['LogDestinationType']!r}"
    )

    # Server-side effect: without any further client action, Redshift itself must have
    # created the CloudWatch Logs log group(s) that back the exported log types.
    expected_prefix = f"/aws/redshift/cluster/{cluster_id}/"
    group_names = _poll_until(
        lambda: [
            g["logGroupName"]
            for g in logs.describe_log_groups(logGroupNamePrefix=expected_prefix).get(
                "logGroups", []
            )
        ],
        lambda names: len(names) > 0,
        timeout_s=300,
        interval_s=15,
    )
    assert any(name.startswith(expected_prefix) for name in group_names), (
        f"expected a log group under prefix {expected_prefix!r}, got {group_names!r}"
    )
    assert any(name.endswith("connectionlog") or name.endswith("userlog") for name in group_names), (
        f"expected a connectionlog or userlog group among {group_names!r}"
    )


def _wait_cluster_status(ctx, cluster_id: str, target_statuses: set[str], *, timeout_s: float, interval_s: float) -> str:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
            "ClusterStatus"
        ]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last status={status!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if predicate(value):
        return value
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
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


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=15.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
