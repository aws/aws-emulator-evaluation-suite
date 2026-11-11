"""delete-cluster-deletion-protection-blocked."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-cluster-deletion-protection-blocked"
GROUP = "negative-classes"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBCluster on a cluster created with DeletionProtection=true fails with InvalidParameterCombination
    and the cluster stays; once ModifyDBCluster disables protection, the identical call deletes it."""
    rds = ctx.client("rds")
    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [s["SubnetId"] for s in az_subnets]

    subnet_group_name = ctx.unique_name("sim2real-rdsdp-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real deletion-protection-blocked test",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name))

    cluster_id = ctx.unique_name("sim2real-rdsdp-cluster-")
    user = "s2radmin"
    password = _master_password()
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername=user,
        MasterUserPassword=password,
        DBSubnetGroupName=subnet_group_name,
        BackupRetentionPeriod=1,
        DeletionProtection=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _safety_net_cleanup() -> None:
        from botocore.exceptions import ClientError

        try:
            rds.modify_db_cluster(
                DBClusterIdentifier=cluster_id, DeletionProtection=False, ApplyImmediately=True
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        rds.get_waiter("db_cluster_deleted").wait(
            DBClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
        )

    ctx.on_cleanup(_safety_net_cleanup)

    deadline = time.monotonic() + 600
    desc = None
    while time.monotonic() < deadline:
        desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if desc["Status"] == "available":
            break
        time.sleep(2)
    assert desc is not None and desc["Status"] == "available", (
        f"cluster {cluster_id!r} never reached 'available' within 600s "
        f"(last status={desc['Status'] if desc else None!r})"
    )
    assert desc["DeletionProtection"] is True, (
        f"cluster {cluster_id!r} should have DeletionProtection=True after creation, "
        f"got {desc['DeletionProtection']!r}"
    )

    # --- negative: delete blocked while DeletionProtection remains enabled ---
    code, message = _error_code(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination for DeleteDBCluster on a deletion-protected "
        f"cluster, got {code!r}"
    )
    assert message == "Cannot delete protected Cluster, please disable deletion protection and try again.", (
        f"unexpected message for DeleteDBCluster on a deletion-protected cluster: {message!r}"
    )

    # Effect absent: the cluster must still exist, still protected, not transitioning to deleted.
    still_there = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert still_there["DeletionProtection"] is True, (
        f"cluster {cluster_id!r} should still have DeletionProtection=True after the rejected "
        f"delete, got {still_there['DeletionProtection']!r}"
    )
    assert still_there["Status"] not in ("deleting", "deleted"), (
        f"cluster {cluster_id!r} should be untouched by the rejected delete, "
        f"got Status={still_there['Status']!r}"
    )

    # --- positive control: disable protection, then the identical delete call succeeds ---
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id, DeletionProtection=False, ApplyImmediately=True
    )
    deadline = time.monotonic() + 120
    protection_now = True
    while time.monotonic() < deadline:
        protection_now = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][
            0
        ]["DeletionProtection"]
        if protection_now is False:
            break
        time.sleep(5)
    assert protection_now is False, (
        f"cluster {cluster_id!r} DeletionProtection never flipped to False within 120s"
    )

    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    rds.get_waiter("db_cluster_deleted").wait(
        DBClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )
    gone_code, gone_message = _error_code(lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id))
    assert gone_code == "DBClusterNotFoundFault", (
        f"cluster {cluster_id!r} should be fully deleted after disabling protection, "
        f"describe returned code={gone_code!r}"
    )
    assert gone_message == f"DBCluster {cluster_id} not found.", (
        f"unexpected not-found message for the deleted cluster: {gone_message!r}"
    )


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
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} for an RDS subnet group"
        )
    return vpc_id, list(by_az.values())[:count]


def _error_code(fn) -> tuple[str, str | None]:
    """Call fn(); return its error code. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
