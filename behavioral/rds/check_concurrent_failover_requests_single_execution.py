"""concurrent-failover-requests-single-execution."""
from __future__ import annotations

import secrets
import string
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-failover-requests-single-execution"
GROUP = "concurrency"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two overlapping FailoverDBCluster calls on an available Aurora cluster run one failover;
    the second, sent while the first is in progress, gets InvalidDBClusterStateFault with its
    exact message."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    versions = rds.describe_db_engine_versions(Engine="aurora-mysql", DefaultOnly=True)[
        "DBEngineVersions"
    ]
    if not versions:
        versions = rds.describe_db_engine_versions(Engine="aurora-mysql")["DBEngineVersions"]
    engine_version = versions[0]["EngineVersion"]

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision the Aurora cluster network")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in at least two availability zones")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group to attach to the cluster")
    sg_id = sgs[0]["GroupId"]

    subnet_group_name = ctx.unique_name("sim2real-failover-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real concurrency check: failover race",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-probe", "Value": CHECK}],
    )

    cluster_id = ctx.unique_name("sim2real-failover-cl-")
    master_password = _generate_master_password()
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        EngineVersion=engine_version,
        MasterUsername="s2radmin",
        MasterUserPassword=master_password,
        DBSubnetGroupName=subnet_group_name,
        VpcSecurityGroupIds=[sg_id],
        Tags=[{"Key": "sim2real-probe", "Value": CHECK}],
    )

    instance_ids = [ctx.unique_name(f"sim2real-failover-i{i}-") for i in range(2)]
    for instance_id in instance_ids:
        rds.create_db_instance(
            DBInstanceIdentifier=instance_id,
            DBClusterIdentifier=cluster_id,
            Engine="aurora-mysql",
            DBInstanceClass="db.r5.large",
            Tags=[{"Key": "sim2real-probe", "Value": CHECK}],
        )

    # One teardown in dependency order: instances, then cluster, then subnet group.
    ctx.on_cleanup(
        lambda: _teardown_cluster(rds, cluster_id, instance_ids, subnet_group_name)
    )

    for instance_id in instance_ids:
        _poll_instance_status(rds, instance_id, "available", timeout_s=_budget_s(ctx, 1200), ctx=ctx)
    _poll_cluster_status(rds, cluster_id, "available", timeout_s=_budget_s(ctx, 300), ctx=ctx)

    successes: list[dict] = []
    failures: list[ClientError] = []

    def _failover():
        try:
            successes.append(rds.failover_db_cluster(DBClusterIdentifier=cluster_id))
        except ClientError as exc:
            failures.append(exc)

    # The first call runs on this thread, so the second follows it with no thread-scheduling gap.
    # It is sent once the cluster has left "available", as the first response or a describe shows.
    _failover()
    if successes and successes[0].get("DBCluster", {}).get("Status", "available") == "available":
        deadline = time.monotonic() + _budget_s(ctx, 60)
        in_flight = False
        while time.monotonic() < deadline:
            status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0][
                "Status"
            ]
            if status != "available":
                in_flight = True
                break
            time.sleep(0.1)
        if not in_flight and _budget_spent(ctx):
            raise TimeoutError("cluster leaving 'available' after the first failover: the run budget ended first; not graded")
        assert in_flight, "first FailoverDBCluster never transitioned the cluster out of 'available'"
    _failover()

    assert len(successes) == 1, f"expected exactly one FailoverDBCluster to succeed, got {len(successes)}"
    assert len(failures) == 1, f"expected exactly one FailoverDBCluster to be rejected, got {len(failures)}"
    code = _error_code_from(failures[0])
    assert code == "InvalidDBClusterStateFault", f"unexpected loser error code: {code}"
    message = failures[0].response["Error"].get("Message", "")
    expected = f"DB cluster:{cluster_id} cannot failover in state:failing-over"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Let the accepted failover run to completion before cleanup tears the cluster down.
    _poll_cluster_status(rds, cluster_id, "available", timeout_s=_budget_s(ctx, 600), ctx=ctx)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error_code_from(exc: ClientError) -> str:
    return exc.response["Error"]["Code"]


def _generate_master_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Sr" + "".join(secrets.choice(alphabet) for _ in range(20)) + "1!"


def _poll_instance_status(rds, instance_id, target_status, timeout_s=1200, interval_s=2, *, ctx) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if desc["DBInstanceStatus"] == target_status:
            return
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"DB instance {instance_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"DB instance {instance_id} never reached status {target_status!r} within {timeout_s}s"
    )


def _poll_cluster_status(rds, cluster_id, target_status, timeout_s=300, interval_s=2, *, ctx) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if desc["Status"] == target_status:
            return
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"DB cluster {cluster_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"DB cluster {cluster_id} never reached status {target_status!r} within {timeout_s}s"
    )


def _poll_instance_gone(rds, instance_id, timeout_s=900, interval_s=2) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as exc:
            if _error_code_from(exc) == "DBInstanceNotFound":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"DB instance {instance_id} was never deleted within {timeout_s}s")


def _poll_cluster_gone(rds, cluster_id, timeout_s=900, interval_s=2) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if _error_code_from(exc) == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"DB cluster {cluster_id} was never deleted within {timeout_s}s")


def _teardown_cluster(rds, cluster_id, instance_ids, subnet_group_name) -> None:
    for instance_id in instance_ids:
        try:
            rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
        except ClientError as exc:
            if _error_code_from(exc) != "DBInstanceNotFound":
                raise
    for instance_id in instance_ids:
        _poll_instance_gone(rds, instance_id)
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if _error_code_from(exc) != "DBClusterNotFoundFault":
            raise
    _poll_cluster_gone(rds, cluster_id)
    rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
