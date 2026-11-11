"""cluster-create-active-delete-state-transition-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-create-active-delete-state-transition-lifecycle"
GROUP = "state-machine"
SERVICES = ["pcs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created cluster transitions CREATING -> ACTIVE, exposes a
    SLURMCTLD control-plane endpoint once ACTIVE, is visible via ListClusters
    while it exists, and cleanly transitions ACTIVE -> (removed) on delete."""
    pcs = ctx.client("pcs")
    subnet_id, security_group_id = _get_default_subnet_and_security_group(ctx)
    cluster_name = ctx.unique_name("sim2real-lifecycle").replace("_", "-")

    create_resp = pcs.create_cluster(
        clusterName=cluster_name,
        scheduler={"type": "SLURM", "version": "25.05"},
        size="SMALL",
        networking={"subnetIds": [subnet_id], "securityGroupIds": [security_group_id]},
    )
    cluster_id = create_resp["cluster"]["id"]
    assert create_resp["cluster"]["status"] == "CREATING", (
        f"expected CreateCluster to report status CREATING, got {create_resp['cluster']['status']!r}"
    )
    ctx.on_cleanup(lambda: _delete_cluster_best_effort(ctx, cluster_id))

    # While CREATING, the cluster is already visible via ListClusters.
    listed = pcs.list_clusters(maxResults=100)["clusters"]
    assert any(c["id"] == cluster_id for c in listed), "cluster missing from ListClusters while CREATING"

    cluster = _poll_until(
        lambda: pcs.get_cluster(clusterIdentifier=cluster_id)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=2400.0,
        interval_s=20.0,
    )
    assert cluster["status"] == "ACTIVE", f"cluster reached {cluster['status']} instead of ACTIVE: {cluster.get('errorInfo')}"

    endpoint_types = {e["type"] for e in cluster.get("endpoints", [])}
    assert "SLURMCTLD" in endpoint_types, f"ACTIVE cluster missing a SLURMCTLD endpoint: {cluster.get('endpoints')}"

    pcs.delete_cluster(clusterIdentifier=cluster_id)

    removed = _poll_until(
        lambda: _get_cluster_or_none(pcs, cluster_id),
        lambda c: c is None,
        timeout_s=1200.0,
        interval_s=15.0,
    )
    assert removed is None, "cluster still exists after delete completed"

    # Effect confirmed: it also disappears from the list view.
    listed_after = pcs.list_clusters(maxResults=100)["clusters"]
    assert all(c["id"] != cluster_id for c in listed_after), "deleted cluster still appears in ListClusters"

    # The dead id is not just absent from reads, it also rejects further mutation.
    try:
        pcs.delete_cluster(clusterIdentifier=cluster_id)
        raise AssertionError("DeleteCluster on an already-deleted cluster id unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException deleting an already-deleted cluster, got {code}"
        )
        message = e.response["Error"].get("Message")
        expected_message = "AWS PCS couldn't find the cluster you specified."
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _get_default_subnet_and_security_group(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("account has no shared network VPC to source networking for PCS")
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
        if cluster["status"] in ("ACTIVE", "SUSPENDED", "CREATE_FAILED"):
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
