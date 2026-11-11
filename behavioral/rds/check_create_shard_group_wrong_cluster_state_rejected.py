"""create-shard-group-wrong-cluster-state-rejected."""
from __future__ import annotations

import json
import secrets
import string
import time

import botocore.exceptions

from behavioral_harness import tags

CHECK = "create-shard-group-wrong-cluster-state-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBShardGroup on a stopped Limitless cluster fails with InvalidDBClusterStateFault and
    creates nothing; the identical call succeeds once the same cluster is started and available.
    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBShardGroup.html"""
    rds = ctx.client("rds")
    iam = ctx.client("iam")
    engine_version = _pick_limitless_engine_version(rds)
    if engine_version is None:
        raise AssertionError("no aurora-postgresql *-limitless engine version available in this region")

    # One teardown, registered before anything exists, drops the monitoring role first: a role
    # that never waits on the cluster's slow delete cannot outlive a teardown that stops partway.
    made: dict[str, str] = {}
    ctx.on_cleanup(lambda: _teardown(ctx, made))
    made["role"] = ctx.unique_name("sim2real-shardstate-mon-")
    monitoring_role_arn = _create_monitoring_role(iam, made["role"])

    cluster_id = ctx.unique_name("sim2real-shardstate-")
    password = _rand_password()
    made["cluster"] = cluster_id
    _create_cluster_with_role_retry(
        rds,
        dict(
            DBClusterIdentifier=cluster_id,
            Engine="aurora-postgresql",
            EngineVersion=engine_version,
            StorageType="aurora-iopt1",
            ClusterScalabilityType="limitless",
            MasterUsername="s2radmin",
            MasterUserPassword=password,
            DeletionProtection=False,
            EnablePerformanceInsights=True,
            PerformanceInsightsRetentionPeriod=31,
            MonitoringInterval=5,
            MonitoringRoleArn=monitoring_role_arn,
            EnableCloudwatchLogsExports=["postgresql"],
            Tags=_TAGS,
        ),
    )

    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=2400)
    rds.stop_db_cluster(DBClusterIdentifier=cluster_id)
    _wait_cluster_status(ctx, cluster_id, "stopped", timeout_s=1800)

    shard_group_id = ctx.unique_name("sim2real-shardgrp-")

    def _early_attempt():
        rds.create_db_shard_group(
            DBShardGroupIdentifier=shard_group_id, DBClusterIdentifier=cluster_id, MaxACU=16, Tags=_TAGS
        )
        # Not rejected: delete the shard group it created whatever the assertions below decide.
        made["shard_group"] = shard_group_id

    code, message = _error(_early_attempt)
    assert (code, message) == (
        "InvalidDBClusterStateFault",
        f"You can't create the DB shard group. The DB cluster {cluster_id} isn't in the AVAILABLE "
        "or CREATING state.",
    ), f"unexpected error {code!r}: {message!r}"

    # Effect absent: no shard group was created.
    absent_code, _ = _error(lambda: rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_group_id))
    assert absent_code == "DBShardGroupNotFound", f"unexpected error code {absent_code!r}"

    # Positive control (same file): once the SAME cluster is started and available, the IDENTICAL
    # create call succeeds.
    rds.start_db_cluster(DBClusterIdentifier=cluster_id)
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=2400)
    rds.create_db_shard_group(
        DBShardGroupIdentifier=shard_group_id, DBClusterIdentifier=cluster_id, MaxACU=16, Tags=_TAGS
    )
    made["shard_group"] = shard_group_id
    created = _wait_shard_group_available(ctx, shard_group_id)
    assert created["DBClusterIdentifier"] == cluster_id, (
        f"expected shard group bound to {cluster_id!r}, got {created['DBClusterIdentifier']!r}"
    )

    # Release within the check's own budget: the shard group goes first, so the cluster delete is
    # not refused for holding one, and the cluster delete is only requested, leaving teardown the
    # one wait for the cluster to disappear.
    _retry_delete_shard_group(ctx, shard_group_id)
    _delete_cluster(ctx, cluster_id, wait=False)


# ===== helpers (self-contained) =====
def _error(fn):
    """``(code, message)`` of the AWS error ``fn()`` raises; a success raises, as AWS refuses the call."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _pick_limitless_engine_version(rds) -> str | None:
    versions = rds.describe_db_engine_versions(Engine="aurora-postgresql")["DBEngineVersions"]
    limitless = [v["EngineVersion"] for v in versions if v["EngineVersion"].endswith("-limitless")]
    return sorted(limitless)[-1] if limitless else None


_ENHANCED_MONITORING_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"


def _create_monitoring_role(iam, role_name: str) -> str:
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
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_ENHANCED_MONITORING_POLICY)
    return arn


def _drop_monitoring_role(iam, role_name: str) -> None:
    """Detach the managed policy and delete the role; either already gone is fine."""
    for drop in (
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_ENHANCED_MONITORING_POLICY),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            drop()
        except iam.exceptions.NoSuchEntityException:
            pass


def _teardown(ctx, made: dict) -> None:
    """Role, then shard group, then cluster: each step runs even if one before it fails, so a
    slow or refused delete never strands the faster ones behind it."""
    steps = []
    if "role" in made:
        steps.append(lambda: _drop_monitoring_role(ctx.client("iam"), made["role"]))
    if "shard_group" in made:
        steps.append(lambda: _retry_delete_shard_group(ctx, made["shard_group"], timeout_s=600))
    if "cluster" in made:
        steps.append(lambda: _delete_cluster(ctx, made["cluster"], timeout_s=1080))
    failures = []
    for step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - every step runs; all failures are raised below
            failures.append(exc)
    if failures:
        raise failures[0] if len(failures) == 1 else AssertionError(f"teardown failed: {failures!r}")


def _create_cluster_with_role_retry(rds, kwargs: dict, timeout_s=120, poll_s=5) -> None:
    """MonitoringRoleArn names a role created moments ago; IAM trust propagation to RDS is
    eventually consistent, so CreateDBCluster transiently rejects it with InvalidParameterValue
    until the role is assumable -- bounded-retry, not a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.create_db_cluster(**kwargs)
            return
        except botocore.exceptions.ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValue":
                raise
            last_exc = exc
            time.sleep(poll_s)
    raise AssertionError(f"CreateDBCluster never accepted the monitoring role within {timeout_s}s: {last_exc}")


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=2400, poll_s=30) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _delete_cluster(ctx, cluster_id, timeout_s=1800, poll_s=10, wait=True) -> None:
    """DeleteDBCluster, retried while a shard group is still leaving, then (``wait``) until the
    cluster is gone. A stopped cluster must be started before it can be deleted, so ``wait=False``
    returns only once the delete is accepted, never leaving a cluster that is merely starting."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"]
            if status == "deleting" and not wait:
                return
            if status == "stopped":
                rds.start_db_cluster(DBClusterIdentifier=cluster_id)
            elif status != "deleting":
                rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
                if not wait:
                    return
        except rds.exceptions.DBClusterNotFoundFault:
            return
        except botocore.exceptions.ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidDBClusterStateFault":
                raise
            last_exc = exc
        time.sleep(poll_s)
    raise AssertionError(f"cluster {cluster_id} not deleted within {timeout_s}s: {last_exc}")


def _retry_delete_shard_group(ctx, shard_group_id, timeout_s=1200, poll_s=20) -> None:
    """DeleteDBShardGroup, retried while the group or its cluster is still settling, then wait
    until the group is gone, so the cluster delete after it is not refused for holding one."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    requested = False
    while time.monotonic() < deadline:
        try:
            if not requested:
                rds.delete_db_shard_group(DBShardGroupIdentifier=shard_group_id)
                requested = True
            rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_group_id)
        except rds.exceptions.DBShardGroupNotFoundFault:
            return
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidDBClusterStateFault", "InvalidDBShardGroupState"):
                raise
            last_exc = exc
        time.sleep(poll_s)
    raise AssertionError(f"shard group {shard_group_id} not deleted within {timeout_s}s: {last_exc}")


def _wait_shard_group_available(ctx, shard_group_id, timeout_s=2400, poll_s=30) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_group_id)["DBShardGroups"][0]
        if last["Status"] == "available":
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"shard group {shard_group_id} never became available, last status {last and last['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
