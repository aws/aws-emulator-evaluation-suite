"""cluster-start-stop-reboot-failover-transitions."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-start-stop-reboot-failover-transitions"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Aurora cluster: available -> stopped -> available, plus rejected reboot/failover."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    # Pin to an ESTABLISHED (one-major-version-back) engine version rather than whatever
    # `Engine="aurora-mysql"` alone resolves to (AWS's current account-wide default, which is
    # routinely the newest major version it has JUST promoted to default). A freshly-promoted
    # major version has measurably thinner pre-warmed provisioning capacity than a
    # long-established one -- and this check runs several slow transitions back-to-back (create,
    # stop, start, plus the two fast negative checks in between), so shaving the create step's
    # provisioning latency matters more here than in a check with only one heavy wait.
    engine_version = _pick_established_engine_version(rds, "aurora-mysql")

    cluster_id = ctx.unique_name("sim2real-behav-cl-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        EngineVersion=engine_version,
        MasterUsername="simadmin",
        MasterUserPassword=_MASTER_PW,
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))

    # Don't wait for the cluster to report "available" before adding its writer instance:
    # CreateDBInstance only needs the cluster to EXIST (it targets it by identifier), not to have
    # finished provisioning yet -- AWS provisions the cluster's storage and the instance's compute
    # concurrently once both calls are in flight. Waiting for cluster-available first would
    # serialize two waits that otherwise overlap, so the total wait is the slower of the two
    # rather than their sum. Waiting on the INSTANCE below is sufficient -- a ready instance
    # implies its cluster is ready too.
    # A widely-stocked x86 burstable class (db.t3.medium) rather than a Graviton class:
    # Graviton (db.t4g.*) Aurora capacity is spottier in some AZs and has been observed to add
    # materially longer provisioning latency than an equivalent x86 class, which matters when the
    # create -> stop -> start sequence runs back-to-back.
    instance_id = ctx.unique_name("sim2real-behav-in-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.t3.medium",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, instance_id))
    # timeout_s is bounded because a stop-wait AND a start-wait follow below -- an established
    # engine version (picked above) keeps this bound comfortably achievable for create.
    _wait_instance_status(ctx, instance_id, {"available"}, timeout_s=480.0, interval_s=10.0)
    # A ready writer instance implies its cluster is ready too (the cluster never reports
    # "available" before the writer does) -- a single describe (no poll loop) confirms it without
    # re-waiting for an already-true fact.
    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert cluster["Status"] == "available", f"expected cluster available, got {cluster['Status']!r}"

    # Negative: RebootDBCluster is restricted to Multi-AZ DB clusters; it is NOT supported for
    # Aurora clusters (Aurora member instances are rebooted individually via RebootDBInstance).
    # The rejection is a static parameter-validation error (engine-type mismatch), not a state
    # change, so it can't have altered the cluster's status -- confirm with a single describe
    # rather than polling again for a fact that's already true.
    code, message = _error_detail(lambda: rds.reboot_db_cluster(DBClusterIdentifier=cluster_id))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected = "Rebooting cluster isn't supported for DB engine aurora-mysql."
    assert message == expected, f"unexpected reboot message: {message!r} (expected {expected!r})"
    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert cluster["Status"] == "available", f"expected cluster available after rejected reboot, got {cluster['Status']!r}"

    # Negative: FailoverDBCluster requires an Aurora Replica; this cluster has none.
    code, message = _error_detail(lambda: rds.failover_db_cluster(DBClusterIdentifier=cluster_id))
    assert code == "InvalidDBClusterStateFault", f"expected InvalidDBClusterStateFault, got {code!r}"
    expected = f"Database cluster:{cluster_id} should have at least two database instances for failover."
    assert message == expected, f"unexpected failover message: {message!r} (expected {expected!r})"

    # available -> stopped. Wait for the cluster AND its instance in a SINGLE poll loop (one
    # describe pair per interval covers both) rather than fully waiting out the cluster before even
    # starting to poll the instance -- if the instance transitions to "stopped" only slightly after
    # the cluster does (or vice versa), a combined loop still only pays for the slower of the two,
    # not the sum.
    rds.stop_db_cluster(DBClusterIdentifier=cluster_id)
    # Stopping an Aurora cluster and its writer takes several minutes; the bound is generous.
    _wait_cluster_and_instance_status(ctx, cluster_id, instance_id, {"stopped"}, timeout_s=900.0, interval_s=10.0)

    # Negative: can't stop an already-stopped cluster.
    code, message = _error_detail(lambda: rds.stop_db_cluster(DBClusterIdentifier=cluster_id))
    assert code == "InvalidDBClusterStateFault", f"expected InvalidDBClusterStateFault, got {code!r}"
    expected = f"DbCluster {cluster_id} is in stopped state but expected it to be one of available."
    assert message == expected, f"unexpected stop message: {message!r} (expected {expected!r})"

    # stopped -> available
    rds.start_db_cluster(DBClusterIdentifier=cluster_id)
    _wait_cluster_and_instance_status(ctx, cluster_id, instance_id, {"available"}, timeout_s=480.0, interval_s=10.0)


def _error_detail(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _pick_established_engine_version(rds, engine: str) -> str:
    """Return the latest MINOR version of the SECOND-newest major version for ``engine``.

    Deliberately avoids the bleeding-edge newest major version (what a bare ``Engine=...``
    create, or ``DefaultOnly=True``, would resolve to): a freshly-promoted-to-default major
    version has measurably thinner pre-warmed provisioning capacity than a long-established
    one -- and this check runs create, stop, AND start back-to-back, so shaving the create
    step's latency matters.

    Aurora MySQL's ``EngineVersion`` strings (e.g. ``"8.0.mysql_aurora.3.05.2"``) embed the
    generationally-meaningful "major" AFTER the ``mysql_aurora.`` marker (``3``, not the
    leading MySQL-compat ``8``) -- grouping by the leading numeral alone would conflate every
    3.x release into one bucket keyed off an unrelated MySQL-compat digit, so that marker is
    checked for first.
    """
    versions = [
        v for v in rds.describe_db_engine_versions(Engine=engine)["DBEngineVersions"]
        if v.get("Status", "available") == "available"
    ]

    def _major(v: str) -> int:
        marker = "mysql_aurora."
        idx = v.find(marker)
        if idx != -1:
            return int(v[idx + len(marker):].split(".")[0])
        return int(v.split(".")[0])

    def _ver_key(v: str):
        return tuple(int(p) if p.isdigit() else p for p in v.split("."))

    majors = sorted({_major(v["EngineVersion"]) for v in versions}, reverse=True)
    target_major = majors[1] if len(majors) > 1 else majors[0]
    candidates = [v["EngineVersion"] for v in versions if _major(v["EngineVersion"]) == target_major]
    assert candidates, f"no {engine} engine versions found for major version {target_major}"
    return sorted(candidates, key=_ver_key)[-1]



def _default_subnet_ids(ctx, count: int = 3) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ids = sorted({s["SubnetId"] for s in subnets})[:count]
    assert len(ids) >= 2, "need at least 2 subnets to create a DB subnet group"
    return ids


def _create_subnet_group(ctx) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=_default_subnet_ids(ctx),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _wait_instance_status(ctx, instance_id: str, statuses: set[str], timeout_s: float = 480.0, interval_s: float = 10.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(probe, lambda i: i["DBInstanceStatus"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_cluster_and_instance_status(
    ctx, cluster_id: str, instance_id: str, statuses: set[str], timeout_s: float = 400.0, interval_s: float = 10.0
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Wait for a DB CLUSTER and its member INSTANCE to BOTH reach one of ``statuses`` in a SINGLE
    poll loop (one describe pair per interval covers both) rather than waiting for each fully in
    turn, so the wait pays for the slower of the two resources once instead of the sum of two
    full sequential waits."""
    rds = ctx.client("rds")

    def probe():
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        return cluster, instance

    return _poll_until(
        probe,
        lambda pair: pair[0]["Status"] in statuses and pair[1]["DBInstanceStatus"] in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _retry_cluster_state(delete, not_found_code: str, deadline: float, interval_s: float) -> None:
    """Teardown: run a delete, tolerating not-found and retrying InvalidDBClusterStateFault while
    the cluster still finishes a stop or start, until the deadline."""
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == not_found_code:
                return
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_instance_and_wait(rds, instance_id: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    """Delete the instance and wait until it is gone, so the cluster, parameter group and subnet
    group torn down after it are no longer in use."""
    deadline = time.monotonic() + timeout_s
    _retry_cluster_state(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True),
        "DBInstanceNotFound",
        deadline,
        interval_s,
    )
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} still exists {timeout_s}s after DeleteDBInstance")


def _delete_cluster_and_wait(rds, cluster_id: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    """Delete the cluster and wait until it is gone, so the parameter group and subnet group torn
    down after it are no longer in use."""
    deadline = time.monotonic() + timeout_s
    _retry_cluster_state(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True),
        "DBClusterNotFoundFault",
        deadline,
        interval_s,
    )
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} still exists {timeout_s}s after DeleteDBCluster")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
