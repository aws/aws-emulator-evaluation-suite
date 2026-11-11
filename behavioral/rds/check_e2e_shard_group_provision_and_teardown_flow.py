"""e2e-shard-group-provision-and-teardown-flow."""
from __future__ import annotations

import json
import secrets
import string
import time


from behavioral_harness import tags

CHECK = "e2e-shard-group-provision-and-teardown-flow"
GROUP = "e2e"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating a shard group on an Aurora PostgreSQL Limitless cluster makes DescribeDBShardGroups
    show one AVAILABLE group; deleting it returns the cluster to its shard-group-less state."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")

    engine_version = _pick_limitless_engine_version(rds)
    if engine_version is None:
        raise AssertionError("no aurora-postgresql *-limitless engine version available in this region")

    role_name = ctx.unique_name("sim2real-monitor-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
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

    cluster_id = ctx.unique_name("sim2real-limitless-")
    password = _rand_password()
    _create_db_cluster_with_retry(
        rds,
        timeout_s=_budget_s(ctx, 300),
        ctx=ctx,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        EngineVersion=engine_version,
        StorageType="aurora-iopt1",
        ClusterScalabilityType="limitless",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        EnablePerformanceInsights=True,
        PerformanceInsightsRetentionPeriod=31,
        MonitoringInterval=60,
        MonitoringRoleArn=role_arn,
        EnableCloudwatchLogsExports=["postgresql"],
        DeletionProtection=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=2400)

    shard_group_id = ctx.unique_name("sim2real-shardgrp-")
    not_found = f"DBShardGroup {shard_group_id} not found."
    baseline = _client_error(
        lambda: rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_group_id)
    )
    assert baseline.get("Code") == "DBShardGroupNotFound", (
        f"expected no shard group to exist yet, got error code {baseline.get('Code')!r}"
    )
    assert baseline.get("Message") == not_found, (
        f"expected message {not_found!r} before creation, got {baseline.get('Message')!r}"
    )

    rds.create_db_shard_group(
        DBShardGroupIdentifier=shard_group_id,
        DBClusterIdentifier=cluster_id,
        MaxACU=16,
        ComputeRedundancy=0,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _delete_shard_group():
        try:
            rds.delete_db_shard_group(DBShardGroupIdentifier=shard_group_id)
        except rds.exceptions.DBShardGroupNotFoundFault:
            pass

    ctx.on_cleanup(_delete_shard_group)

    sg = _wait_shard_group_status(ctx, shard_group_id, "available", timeout_s=2400)
    assert sg["DBClusterIdentifier"] == cluster_id, (
        f"shard group reports DBClusterIdentifier {sg['DBClusterIdentifier']!r}, expected {cluster_id!r}"
    )
    # The cluster itself can still be transitioning even once the shard group reports
    # "available"; DeleteDBShardGroup requires the CLUSTER to be in AVAILABLE state.
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=600)

    _retry_delete_shard_group(ctx, shard_group_id, timeout_s=600)
    _wait_shard_group_gone(ctx, shard_group_id, timeout_s=2400)

    reverted = _client_error(
        lambda: rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_group_id)
    )
    assert reverted.get("Code") == "DBShardGroupNotFound", (
        f"cluster shard topology did not revert, describe returned error {reverted.get('Code')!r}"
    )
    assert reverted.get("Message") == not_found, (
        f"expected message {not_found!r} after deletion, got {reverted.get('Message')!r}"
    )

    # The shard group vanishing does not mean the cluster has settled: it stays "modifying"
    # for a while afterward, so this is a bounded wait.
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=1800)


def _client_error(fn) -> dict:
    """The botocore Error dict fn() raised. An unexpected SUCCESS raises instead."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            return response.get("Error", {})
        raise
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _create_db_cluster_with_retry(rds, *, timeout_s: float, ctx=None, **kwargs) -> None:
    """CreateDBCluster's MonitoringRoleArn can be rejected while the freshly-created IAM role's
    trust policy has not yet propagated to be assumable by monitoring.rds.amazonaws.com;
    bounded-retry, not a bare sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.create_db_cluster(**kwargs)
            return
        except Exception as exc:  # noqa: BLE001 - IAM propagation lag, retry until the budget runs out
            last_exc = exc
            time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("CreateDBCluster accepted: the run budget ended first; not graded") from last_exc
    raise AssertionError(f"CreateDBCluster did not succeed within {timeout_s}s (IAM propagation?): {last_exc!r}")


def _retry_delete_shard_group(ctx, shard_group_id, timeout_s=600, poll_s=2) -> None:
    """DeleteDBShardGroup transiently rejects with InvalidDBClusterStateFault while the
    parent cluster is still settling post-shard-group-creation; bounded-retry, not one shot."""
    import botocore.exceptions

    rds = ctx.client("rds")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.delete_db_shard_group(DBShardGroupIdentifier=shard_group_id)
            return
        except botocore.exceptions.ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidDBClusterStateFault":
                raise
            last_exc = exc
            time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError("DeleteDBShardGroup accepted: the run budget ended first; not graded") from last_exc
    raise AssertionError(f"DeleteDBShardGroup never became valid within {timeout_s}s: {last_exc}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _pick_limitless_engine_version(rds) -> str | None:
    versions = rds.describe_db_engine_versions(Engine="aurora-postgresql")["DBEngineVersions"]
    limitless = [v["EngineVersion"] for v in versions if v["EngineVersion"].endswith("-limitless")]
    return sorted(limitless)[-1] if limitless else None


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=2400, poll_s=2) -> dict:
    rds = ctx.client("rds")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_shard_group_status(ctx, shard_group_id, target_status, timeout_s=2400, poll_s=2) -> dict:
    rds = ctx.client("rds")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_group_id)["DBShardGroups"][
            0
        ]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"shard group {shard_group_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"shard group {shard_group_id} never reached {target_status!r}, "
        f"last status {last and last['Status']!r}"
    )


def _wait_shard_group_gone(ctx, shard_group_id, timeout_s=600, poll_s=2) -> None:
    rds = ctx.client("rds")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_group_id)
        except rds.exceptions.DBShardGroupNotFoundFault:
            return
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"shard group {shard_group_id} gone: the run budget ended first; not graded")
    raise AssertionError(f"shard group {shard_group_id} was still visible after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
