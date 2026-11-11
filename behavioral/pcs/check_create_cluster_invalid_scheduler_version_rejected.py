"""create-cluster-invalid-scheduler-version-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-invalid-scheduler-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster with an unsupported Slurm version gets ValidationException with its exact message
    and creates no cluster, and ListClusters still returns a clusters list."""
    pcs = ctx.client("pcs")
    subnet_id, _vpc_id = _get_default_subnet(ctx)
    cluster_name = ctx.unique_name("sim2real-badver").replace("_", "-")

    error = None
    try:
        result = pcs.create_cluster(
            clusterName=cluster_name,
            scheduler={"type": "SLURM", "version": "1.0-not-a-real-version"},
            size="SMALL",
            networking={"subnetIds": [subnet_id]},
        )
    except ClientError as e:
        error = e.response.get("Error", {})
    else:
        raise AssertionError(f"CreateCluster with a bad scheduler version SUCCEEDED: {result!r}")

    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException, got {error.get('Code')!r}"
    )
    expected_message = "Scheduler version not found: type=SLURM, version=1.0-not-a-real-version"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent: no cluster was created under that name.
    clusters = pcs.list_clusters(maxResults=100).get("clusters", [])
    assert all(c["name"] != cluster_name for c in clusters), "cluster was created despite bad version"

    # Positive control: the service/client is otherwise healthy.
    resp = pcs.list_clusters(maxResults=1)
    assert isinstance(resp.get("clusters"), list), f"expected a clusters list, got {resp.get('clusters')!r}"


def _get_default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("account has no shared network VPC to source a subnet for PCS networking config")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no subnets to source for PCS networking config")
    return subnets[0]["SubnetId"], vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
