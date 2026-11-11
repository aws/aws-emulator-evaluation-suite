"""concurrent-failover-requests-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
import secrets

CHECK = "concurrent-failover-requests-single-winner"
GROUP = "concurrency"
SERVICES = ["rds"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """Of two FailoverDBCluster calls on one Aurora cluster, the second issued while the first is in flight,
    exactly one succeeds and the other fails with InvalidDBClusterStateFault, and the cluster returns to
    available: failover is serialized per cluster, not double-applied."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    cluster_id = ctx.unique_name("sim2real-rds-fo-")
    writer_id = f"{cluster_id}-w"
    reader_id = f"{cluster_id}-r"
    instance_class = "db.t3.medium"

    subnet_ids = _resolve_multi_az_subnets(ec2, ctx=ctx)
    subnet_group_name = ctx.unique_name("sim2real-rds-fo-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real concurrency check: failover single winner",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name))

    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="sim2real",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        DBSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))
    _wait_for_cluster_status(rds, cluster_id, {"available"}, timeout_s=1200, interval_s=20)

    with ThreadPoolExecutor(max_workers=2) as pool:
        create_futs = []
        for instance_id in (writer_id, reader_id):
            create_futs.append(
                pool.submit(
                    rds.create_db_instance,
                    DBInstanceIdentifier=instance_id,
                    DBInstanceClass=instance_class,
                    Engine="aurora-mysql",
                    DBClusterIdentifier=cluster_id,
                    Tags=[{"Key": "sim2real", "Value": "true"}],
                )
            )
        for fut in create_futs:
            fut.result()
    for instance_id in (writer_id, reader_id):
        ctx.on_cleanup(lambda i=instance_id: _delete_instance(rds, i))

    for instance_id in (writer_id, reader_id):
        _wait_for_instance_status(rds, instance_id, {"available"}, timeout_s=1800, interval_s=20)

    def _failover():
        return rds.failover_db_cluster(DBClusterIdentifier=cluster_id)

    # A truly simultaneous submission of both calls is not sufficient to reliably land the
    # second one *while the first is in flight*: dispatch latency can let the second arrive
    # after the first has already completed, in which case both legitimately succeed as two
    # sequential failovers -- not a race at all, and a false failure below. Fire the first call
    # in the background, busy-poll until the cluster status leaves "available" (proof the first
    # call has been accepted and is executing), and only then issue the second synchronously.
    with ThreadPoolExecutor(max_workers=1) as pool:
        first_fut = pool.submit(lambda: _capture(_failover))

        deadline = time.monotonic() + 60
        in_flight = False
        while time.monotonic() < deadline:
            status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"]
            if status != "available":
                in_flight = True
                break
            time.sleep(0.1)
        assert in_flight, "first FailoverDBCluster never transitioned the cluster out of 'available'"

        outcome2 = _capture(_failover)
        outcome1 = first_fut.result()

    outcomes = [outcome1, outcome2]
    successes = [o for o in outcomes if o["ok"]]
    failures = [o for o in outcomes if not o["ok"]]
    assert len(successes) == 1, f"expected exactly one FailoverDBCluster to succeed: {outcomes}"
    assert len(failures) == 1, f"expected exactly one FailoverDBCluster to fail: {outcomes}"
    assert failures[0]["code"] == "InvalidDBClusterStateFault", failures[0]
    assert successes[0]["result"]["DBCluster"]["Status"] in ("failing-over", "available"), successes[0]

    _wait_for_cluster_status(rds, cluster_id, {"available"}, timeout_s=1200, interval_s=20)


def _resolve_multi_az_subnets(ec2, *, ctx) -> list[str]:
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
    return subnet_ids


def _capture(fn):
    from botocore.exceptions import ClientError

    try:
        return {"ok": True, "result": fn()}
    except ClientError as exc:
        return {"ok": False, "code": exc.response["Error"]["Code"]}


def _wait_for_cluster_status(rds, cluster_id, ok_statuses, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        last = resp["DBClusters"][0]
        if last["Status"] in ok_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached {ok_statuses} within {timeout_s}s; "
        f"last status={(last.get('Status') if last else None)!r}"
    )


def _wait_for_instance_status(rds, instance_id, ok_statuses, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        last = resp["DBInstances"][0]
        if last["DBInstanceStatus"] in ok_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"instance {instance_id} never reached {ok_statuses} within {timeout_s}s; "
        f"last status={(last.get('DBInstanceStatus') if last else None)!r}"
    )


def _delete_instance(rds, instance_id):
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
            return
        raise
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
                return
            raise
        time.sleep(20)


def _delete_cluster(rds, cluster_id):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBClusterNotFoundFault":
                return
            if code == "InvalidDBClusterStateFault":
                time.sleep(20)
                continue
            raise
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(20)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
