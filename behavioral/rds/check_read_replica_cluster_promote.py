"""read-replica-cluster-promote."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "read-replica-cluster-promote"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PromoteReadReplicaDBCluster on an available Aurora cluster that is not a read replica is rejected
    with InvalidDBClusterStateFault and leaves the cluster available with no replication source."""
    rds = ctx.client("rds")

    sng = _subnet_group(ctx)
    cluster_id = ctx.unique_name("sim2real-nonreplclu-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2RealBehav1!",
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        StorageEncrypted=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))

    inst_id = ctx.unique_name("sim2real-nonreplinst-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id, DBInstanceClass="db.t3.medium", Engine="aurora-mysql",
        DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    _wait_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c["Status"] == "available",
        timeout_s=1800, interval_s=30, desc="cluster available",
    )

    try:
        rds.promote_read_replica_db_cluster(DBClusterIdentifier=cluster_id)
        raise AssertionError("PromoteReadReplicaDBCluster on a non-replica cluster unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        assert code == "InvalidDBClusterStateFault", f"expected InvalidDBClusterStateFault, got {code!r}"
        expected = "You cannot promote a DB cluster that is not a read replica."
        assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # Positive control: the rejected call did not mutate the cluster.
    unchanged = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert unchanged["Status"] == "available", f"expected status available, got {unchanged['Status']!r}"
    assert "ReplicationSourceIdentifier" not in unchanged, (
        f"expected no ReplicationSourceIdentifier on a non-replica cluster, got "
        f"{unchanged.get('ReplicationSourceIdentifier')!r}"
    )


def _wait_until(probe, predicate, timeout_s, interval_s=20, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last}")
        time.sleep(interval_s)


def _wait_gone(probe, not_found_codes, timeout_s, interval_s=20, desc="deletion"):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            probe()
        except ClientError as e:
            if e.response["Error"]["Code"] in not_found_codes:
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}")
        time.sleep(interval_s)


def _subnet_group(ctx, name_prefix="sim2real-sng-"):

    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build a DB subnet group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span enough AZs for a DB subnet group")
    name = ctx.unique_name(name_prefix)
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids[:3],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _delete_instance(rds, inst_id):
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id),
        {"DBInstanceNotFound"}, timeout_s=1200, interval_s=20, desc=f"instance {inst_id} deleted",
    )


def _delete_cluster(rds, cluster_id):
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id),
        {"DBClusterNotFoundFault"}, timeout_s=1200, interval_s=20, desc=f"cluster {cluster_id} deleted",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
