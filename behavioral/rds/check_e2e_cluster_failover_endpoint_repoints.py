"""e2e-cluster-failover-endpoint-repoints."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-cluster-failover-endpoint-repoints"
GROUP = "e2e"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FailoverDBCluster on a 2-instance Aurora cluster promotes the target reader and demotes the
    old writer in DBClusterMembers, and both instances are then available.
    """
    rds = ctx.client("rds")
    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [s["SubnetId"] for s in az_subnets]

    subnet_group_name = ctx.unique_name("sim2real-rdsfo-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real cluster-failover behavioral test",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name))

    cluster_id = ctx.unique_name("sim2real-rdsfo-cluster-")
    user = "s2radmin"
    password = _master_password()
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername=user,
        MasterUserPassword=password,
        DBSubnetGroupName=subnet_group_name,
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _cleanup_cluster() -> None:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        rds.get_waiter("db_cluster_deleted").wait(
            DBClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
        )

    ctx.on_cleanup(_cleanup_cluster)

    writer_id = ctx.unique_name("sim2real-rdsfo-inst-a-")
    reader_id = ctx.unique_name("sim2real-rdsfo-inst-b-")
    for instance_id in (writer_id, reader_id):
        rds.create_db_instance(
            DBInstanceIdentifier=instance_id,
            DBInstanceClass="db.r5.large",
            Engine="aurora-postgresql",
            DBClusterIdentifier=cluster_id,
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )

        def _cleanup_instance(iid=instance_id) -> None:
            rds.delete_db_instance(DBInstanceIdentifier=iid)
            rds.get_waiter("db_instance_deleted").wait(
                DBInstanceIdentifier=iid, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
            )

        ctx.on_cleanup(_cleanup_instance)

    from botocore.exceptions import WaiterError

    for instance_id in (writer_id, reader_id):
        try:
            rds.get_waiter("db_instance_available").wait(
                DBInstanceIdentifier=instance_id,
                WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 1800) // 2))},
            )
        except WaiterError as exc:
            if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
                raise TimeoutError(f"instance {instance_id} available: the run budget ended first; not graded") from exc
            raise

    # Both instances were created without waiting, so either may be the writer; read the roles.
    members_before = _cluster_members(rds, cluster_id)
    pre_writer = _writer_of(members_before)
    assert pre_writer in (writer_id, reader_id), (
        f"expected one of {writer_id!r}/{reader_id!r} to be the pre-failover writer, got "
        f"{pre_writer!r} (members={members_before})"
    )
    if pre_writer == reader_id:
        writer_id, reader_id = reader_id, writer_id
    pre_reader_role = members_before[reader_id]
    assert pre_reader_role is False, f"expected {reader_id!r} to be a reader before failover"

    rds.failover_db_cluster(DBClusterIdentifier=cluster_id, TargetDBInstanceIdentifier=reader_id)

    # Poll until the cluster settles AND the role flip is actually recorded — status alone can
    # flip back to 'available' before DBClusterMembers reflects the new writer.
    flip_s = _budget_s(ctx, 900)
    deadline = time.monotonic() + flip_s
    members_after = None
    while time.monotonic() < deadline:
        desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if desc["Status"] == "available":
            members_after = _cluster_members(rds, cluster_id)
            if members_after.get(reader_id) is True and members_after.get(writer_id) is False:
                break
        time.sleep(2)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(f"cluster {cluster_id!r} failover role flip: the run budget ended first; not graded")
        raise AssertionError(
            f"cluster {cluster_id!r} never completed the role flip within {flip_s:.0f}s; "
            f"last members={members_after}"
        )

    assert members_after[reader_id] is True, (
        f"expected former reader {reader_id!r} to be promoted to writer, members={members_after}"
    )
    assert members_after[writer_id] is False, (
        f"expected former writer {writer_id!r} to be demoted to reader, members={members_after}"
    )

    for instance_id in (writer_id, reader_id):
        status = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
            "DBInstanceStatus"
        ]
        assert status == "available", (
            f"expected {instance_id!r} 'available' after failover, got {status!r}"
        )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _master_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
    """Return (vpc_id, [subnet, ...]) covering `count` distinct AZs, for a DBSubnetGroup."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < count:
        raise AssertionError(
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} for an "
            f"Aurora cluster subnet group"
        )
    return vpc_id, list(by_az.values())[:count]


def _cluster_members(rds, cluster_id: str) -> dict[str, bool]:
    """{instance_identifier: is_cluster_writer} for the cluster's current members."""
    desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    return {m["DBInstanceIdentifier"]: m["IsClusterWriter"] for m in desc["DBClusterMembers"]}


def _writer_of(members: dict[str, bool]) -> str | None:
    writers = [iid for iid, is_writer in members.items() if is_writer]
    return writers[0] if len(writers) == 1 else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
