"""update-cluster-invalid-scheduler-version-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-cluster-invalid-scheduler-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCluster with an unsupported Slurm version gets ValidationException with its exact message
    and leaves the cluster ACTIVE on its original version, while an update of scaleDownIdleTimeInSeconds
    to 700 on the same cluster succeeds."""
    pcs = ctx.client("pcs")
    subnet_id, security_group_id = _get_default_subnet_and_security_group(ctx)
    cluster_name = ctx.unique_name("sim2real-badupdver").replace("_", "-")
    original_version = "25.05"

    create_resp = pcs.create_cluster(
        clusterName=cluster_name,
        scheduler={"type": "SLURM", "version": original_version},
        size="SMALL",
        networking={"subnetIds": [subnet_id], "securityGroupIds": [security_group_id]},
    )
    cluster_id = create_resp["cluster"]["id"]
    ctx.on_cleanup(lambda: _delete_cluster_best_effort(ctx, cluster_id))

    cluster = _poll_until(
        lambda: pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=2400.0,
        interval_s=20.0,
    )
    assert cluster["status"] == "ACTIVE", f"cluster reached {cluster['status']} instead of ACTIVE"
    assert cluster["scheduler"]["version"] == original_version, (
        f"expected persisted version {original_version!r}, got {cluster['scheduler']['version']!r}"
    )

    # --- invalid target version is rejected ---
    code = message = None
    try:
        pcs.update_cluster(
            clusterIdentifier=cluster_id,
            scheduler={"version": "1.0-not-a-real-version"},
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "AWS PCS doesn't support the scheduler version you provided."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the persisted version is unchanged and the cluster
    # never left ACTIVE for this rejected request.
    unchanged = pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"]
    assert unchanged["scheduler"]["version"] == original_version, (
        f"expected version to remain {original_version!r} after rejected update, "
        f"got {unchanged['scheduler']['version']!r}"
    )
    assert unchanged["status"] == "ACTIVE", (
        f"expected cluster to remain ACTIVE after rejected update, got {unchanged['status']!r}"
    )

    # --- positive control: a legitimate update still succeeds ---
    updated = pcs.update_cluster(
        clusterIdentifier=cluster_id,
        slurmConfiguration={"scaleDownIdleTimeInSeconds": 700},
    )["cluster"]
    assert updated["status"] in ("UPDATING", "ACTIVE"), (
        f"expected legitimate update to move to UPDATING or ACTIVE, got {updated['status']!r}"
    )
    updated = _poll_until(
        lambda: pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert updated["status"] == "ACTIVE", f"update reached {updated['status']} instead of ACTIVE"
    assert updated["slurmConfiguration"]["scaleDownIdleTimeInSeconds"] == 700, (
        f"expected scaleDownIdleTimeInSeconds 700, got {updated['slurmConfiguration'].get('scaleDownIdleTimeInSeconds')!r}"
    )
    assert updated["scheduler"]["version"] == original_version, (
        f"expected scheduler version to remain {original_version!r} across unrelated update, "
        f"got {updated['scheduler']['version']!r}"
    )


def _get_default_subnet_and_security_group(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("account has no shared network VPC to source a subnet for PCS networking config")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no subnets to source for PCS networking config")
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    if not groups:
        raise AssertionError("shared network has no default security group to source for PCS networking config")
    return subnets[0]["SubnetId"], groups[0]["GroupId"]


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _get_cluster_or_none(pcs, cluster_id):
    try:
        return pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _delete_cluster_best_effort(ctx, cluster_id, timeout_s=2400.0, interval_s=20.0) -> None:
    pcs = ctx.client("pcs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = _get_cluster_or_none(pcs, cluster_id)
        if cluster is None:
            return
        if cluster["status"] in ("ACTIVE", "SUSPENDED", "CREATE_FAILED", "UPDATE_FAILED"):
            try:
                pcs.delete_cluster(clusterIdentifier=cluster_id)
            except ClientError as e:
                if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
                    raise
            return
        if cluster["status"] == "DELETING":
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
