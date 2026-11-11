"""create-cluster-backup-retention-out-of-range-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-cluster-backup-retention-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBCluster with BackupRetentionPeriod=40 (outside 1-35) is rejected with
    InvalidParameterValue, not clamped, while an otherwise identical cluster with 7 is created."""
    rds = ctx.client("rds")
    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [s["SubnetId"] for s in az_subnets]

    subnet_group_name = ctx.unique_name("sim2real-rdsbr-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real backup-retention-range rejection test",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name))

    user = "s2radmin"
    password = _admin_password()

    # --- negative: BackupRetentionPeriod above the documented 35-day maximum ---
    bad_id = ctx.unique_name("sim2real-rdsbr-bad-")
    code, message = _error_code(
        lambda: rds.create_db_cluster(
            DBClusterIdentifier=bad_id,
            Engine="aurora-postgresql",
            MasterUsername=user,
            MasterUserPassword=password,
            DBSubnetGroupName=subnet_group_name,
            BackupRetentionPeriod=40,
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for BackupRetentionPeriod=40, got {code!r}"
    )
    expected = "Invalid backup retention period: 40. Retention period must be between 1 and 35."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected cluster must not exist afterwards.
    not_found_code, not_found_message = _error_code(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=bad_id)
    )
    assert not_found_code == "DBClusterNotFoundFault", (
        f"rejected cluster {bad_id!r} should not exist, but describe returned "
        f"code={not_found_code!r} instead of DBClusterNotFoundFault"
    )
    expected_nf = f"DBCluster {bad_id} not found."
    assert not_found_message == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found_message!r}"
    )

    # --- positive control: a value inside the range succeeds and persists exactly ---
    good_id = ctx.unique_name("sim2real-rdsbr-good-")
    rds.create_db_cluster(
        DBClusterIdentifier=good_id,
        Engine="aurora-postgresql",
        MasterUsername=user,
        MasterUserPassword=password,
        DBSubnetGroupName=subnet_group_name,
        BackupRetentionPeriod=7,
    )

    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, good_id))

    deadline = time.monotonic() + 600
    status = None
    while time.monotonic() < deadline:
        desc = rds.describe_db_clusters(DBClusterIdentifier=good_id)["DBClusters"][0]
        status = desc["Status"]
        if status == "available":
            break
        time.sleep(2)
    assert status == "available", (
        f"positive-control cluster {good_id!r} never reached 'available' within 600s "
        f"(last status={status!r})"
    )
    assert desc["BackupRetentionPeriod"] == 7, (
        f"positive-control cluster {good_id!r} should have BackupRetentionPeriod=7, "
        f"got {desc['BackupRetentionPeriod']!r}"
    )


def _admin_password() -> str:
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


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_cluster_and_wait(rds, cluster_id: str, timeout_s: float = 900) -> None:
    """Teardown: DeleteDBCluster is asynchronous, and the subnet group cannot be deleted while
    the cluster still exists, so wait (bounded) until the cluster is gone."""
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(10)
    raise AssertionError(f"cluster {cluster_id} still present {timeout_s}s after DeleteDBCluster")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
