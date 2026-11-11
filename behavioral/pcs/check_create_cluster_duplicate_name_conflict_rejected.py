"""create-cluster-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster with the name of an ACTIVE cluster gets ConflictException with its exact message
    and leaves one unchanged cluster of that name, and UpdateCluster on it still succeeds and persists
    scaleDownIdleTimeInSeconds 900."""
    pcs = ctx.client("pcs")
    subnet_id, security_group_id = _get_default_subnet_and_sg(ctx)
    cluster_name = ctx.unique_name("sim2real-dupname").replace("_", "-")

    create_resp = pcs.create_cluster(
        clusterName=cluster_name,
        scheduler={"type": "SLURM", "version": "25.05"},
        size="SMALL",
        networking={"subnetIds": [subnet_id], "securityGroupIds": [security_group_id]},
        tags={"Name": cluster_name, "sim2real:managed": "true"},
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
    original_created_at = cluster["createdAt"]

    # --- duplicate name is rejected ---
    try:
        pcs.create_cluster(
            clusterName=cluster_name,
            scheduler={"type": "SLURM", "version": "25.05"},
            size="SMALL",
            networking={"subnetIds": [subnet_id], "securityGroupIds": [security_group_id]},
        )
    except ClientError as e:
        err = e.response["Error"]
    else:
        raise AssertionError(f"CreateCluster with the duplicate name {cluster_name!r} succeeded; expected ConflictException")
    assert err["Code"] == "ConflictException", f"expected ConflictException, got {err['Code']}"
    expected_message = "A cluster with the name you specified already exists."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: there is still exactly one cluster with that name, and it
    # is the original one (unchanged createdAt), not a freshly re-created one.
    listed = pcs.list_clusters(maxResults=100)["clusters"]
    same_name = [c for c in listed if c["name"] == cluster_name]
    assert len(same_name) == 1, f"expected exactly 1 cluster named {cluster_name}, found {len(same_name)}"
    unchanged = pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"]
    assert unchanged["createdAt"] == original_created_at, (
        f"expected createdAt to stay {original_created_at!r}, got {unchanged['createdAt']!r}"
    )
    assert unchanged["status"] == "ACTIVE", f"expected status ACTIVE, got {unchanged['status']!r}"

    # --- positive control: a real update still works and persists ---
    updated = pcs.update_cluster(
        clusterIdentifier=cluster_id,
        slurmConfiguration={"scaleDownIdleTimeInSeconds": 900},
    )["cluster"]
    assert updated["status"] in ("UPDATING", "ACTIVE"), (
        f"expected UpdateCluster response status UPDATING or ACTIVE, got {updated['status']!r}"
    )
    updated = _poll_until(
        lambda: pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert updated["status"] == "ACTIVE", f"update reached {updated['status']} instead of ACTIVE"
    assert updated["slurmConfiguration"]["scaleDownIdleTimeInSeconds"] == 900, (
        f"expected scaleDownIdleTimeInSeconds=900 to persist, got "
        f"{updated['slurmConfiguration']['scaleDownIdleTimeInSeconds']!r}"
    )


def _get_default_subnet_and_sg(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("account has no shared network VPC to source a subnet for PCS networking config")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no subnets to source for PCS networking config")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError("shared network has no default security group to source for PCS networking config")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


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
