"""deletion-protection-server-enforced-gate."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deletion-protection-server-enforced-gate"
GROUP = "server-side"
SERVICES = ["rds"]

_PROTECTED_MSG = "Cannot delete protected Cluster, please disable deletion protection and try again."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With DeletionProtection turned on by ModifyDBCluster, DeleteDBCluster is refused, a retry of it is
    refused again, and a ModifyDBCluster of BackupRetentionPeriod leaves the flag on; only a
    ModifyDBCluster that disables DeletionProtection lets the identical delete succeed."""
    rds = ctx.client("rds")
    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [s["SubnetId"] for s in az_subnets]

    subnet_group_name = ctx.unique_name("sim2real-rdsdpg-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real deletion-protection-gate test",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name))

    cluster_id = ctx.unique_name("sim2real-rdsdpg-cluster-")
    user = "s2radmin"
    password = _master_password()
    # Create WITHOUT DeletionProtection, then flip it on via ModifyDBCluster -- proving the gate
    # is enforced regardless of whether protection was set at creation or added later.
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername=user,
        MasterUserPassword=password,
        DBSubnetGroupName=subnet_group_name,
        BackupRetentionPeriod=1,
        DeletionProtection=False,
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

    desc = _wait_for_cluster_status(rds, cluster_id, "available", timeout_s=600)
    assert desc is not None and desc["Status"] == "available", (
        f"cluster {cluster_id!r} never reached 'available' within 600s "
        f"(last status={desc['Status'] if desc else None!r})"
    )
    assert desc["DeletionProtection"] is False, (
        f"cluster {cluster_id!r} should have DeletionProtection=False right after creation, "
        f"got {desc['DeletionProtection']!r}"
    )

    # --- turn protection on ---
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id, DeletionProtection=True, ApplyImmediately=True
    )
    desc = _wait_for_deletion_protection(rds, cluster_id, want=True, timeout_s=120)
    assert desc["DeletionProtection"] is True, (
        f"cluster {cluster_id!r} DeletionProtection never flipped to True within 120s"
    )

    # --- first delete attempt: blocked ---
    code, message = _client_error(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination for DeleteDBCluster on a deletion-protected "
        f"cluster, got {code!r}"
    )
    assert message == _PROTECTED_MSG, message
    still_there = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert still_there["Status"] not in ("deleting", "deleted"), (
        f"cluster {cluster_id!r} should be untouched by the rejected delete, "
        f"got Status={still_there['Status']!r}"
    )

    # --- caller retry of the IDENTICAL delete: blocked again, not a one-shot gate ---
    code_retry, message_retry = _client_error(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    assert code_retry == "InvalidParameterCombination", (
        f"retrying the same DeleteDBCluster must still be rejected, got {code_retry!r}"
    )
    assert message_retry == _PROTECTED_MSG, message_retry
    still_there_retry = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert still_there_retry["DeletionProtection"] is True, (
        f"cluster {cluster_id!r} DeletionProtection should still read True after the rejected "
        f"retry, got {still_there_retry['DeletionProtection']!r}"
    )
    assert still_there_retry["Status"] not in ("deleting", "deleted"), (
        f"cluster {cluster_id!r} should be untouched by the rejected retry, "
        f"got Status={still_there_retry['Status']!r}"
    )

    # --- an unrelated ModifyDBCluster (BackupRetentionPeriod) must not clear protection ---
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id, BackupRetentionPeriod=3, ApplyImmediately=True
    )
    desc_after_unrelated = _wait_for_backup_retention(rds, cluster_id, want=3, timeout_s=120)
    assert desc_after_unrelated["BackupRetentionPeriod"] == 3, (
        "unrelated modify never took effect (BackupRetentionPeriod never reached 3)"
    )
    assert desc_after_unrelated["DeletionProtection"] is True, (
        "DeletionProtection was cleared by an unrelated ModifyDBCluster call that never "
        "mentioned it"
    )
    code_after_unrelated, message_after_unrelated = _client_error(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    assert code_after_unrelated == "InvalidParameterCombination", (
        f"delete must still be blocked after an unrelated modify, got {code_after_unrelated!r}"
    )
    assert message_after_unrelated == _PROTECTED_MSG, message_after_unrelated

    # --- positive control: explicitly disable protection, then delete succeeds ---
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id, DeletionProtection=False, ApplyImmediately=True
    )
    desc_disabled = _wait_for_deletion_protection(rds, cluster_id, want=False, timeout_s=120)
    assert desc_disabled["DeletionProtection"] is False, (
        f"cluster {cluster_id!r} DeletionProtection never flipped to False within 120s"
    )

    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    rds.get_waiter("db_cluster_deleted").wait(
        DBClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )
    gone_code, gone_message = _client_error(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
    )
    assert gone_code == "DBClusterNotFoundFault", (
        f"cluster {cluster_id!r} should be fully deleted after disabling protection, "
        f"describe returned code={gone_code!r}"
    )
    assert gone_message == f"DBCluster {cluster_id} not found.", gone_message


def _master_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
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


def _wait_for_cluster_status(rds, cluster_id: str, want: str, timeout_s: float) -> dict | None:
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if desc["Status"] == want:
            return desc
        time.sleep(2)
    return desc


def _wait_for_deletion_protection(rds, cluster_id: str, want: bool, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    while time.monotonic() < deadline:
        desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if desc["DeletionProtection"] is want:
            return desc
        time.sleep(5)
    return desc


def _wait_for_backup_retention(rds, cluster_id: str, want: int, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    while time.monotonic() < deadline:
        desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if desc["BackupRetentionPeriod"] == want:
            return desc
        time.sleep(5)
    return desc


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
