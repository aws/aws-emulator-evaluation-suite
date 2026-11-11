"""create-cluster-reserved-name-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-reserved-name-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["pcs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster with a clusterName that fails the name pattern (a "pcs_" prefix with an underscore)
    gets ValidationException with its exact message and creates no cluster, and ListClusters still
    answers."""
    pcs = ctx.client("pcs")
    subnet_id, _vpc_id = _get_default_subnet(ctx)

    bad_name = "pcs_" + ctx.unique_name("badname").replace("-", "")
    code = None
    message = None
    try:
        pcs.create_cluster(
            clusterName=bad_name,
            scheduler={"type": "SLURM", "version": "25.05"},
            size="SMALL",
            networking={"subnetIds": [subnet_id]},
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")

    assert code == "ValidationException", f"expected ValidationException, got {code}|{message}"
    expected = (
        "1 validation error(s) detected: Value at 'clusterName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: (?!pcs_)^[A-Za-z][A-Za-z0-9-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: nothing with that (rejected) name exists anywhere in the account.
    clusters = pcs.list_clusters(maxResults=100).get("clusters", [])
    assert all(c["name"] != bad_name for c in clusters), "rejected cluster name was created anyway"

    # Positive control: the client/service is not wedged by the rejection --
    # an ordinary read-only call on the same client still succeeds.
    resp = pcs.list_clusters(maxResults=1)
    clusters_field = resp.get("clusters")
    assert isinstance(clusters_field, list), f"expected list_clusters to still respond normally, got clusters={clusters_field!r}"


def _get_default_subnet(ctx):
    """A subnet in a VPC this check creates; both are removed at cleanup."""
    ec2 = ctx.client("ec2")
    tags = [{"Key": "sim2real-check", "Value": CHECK}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    zone = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.0.1.0/24",
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id, vpc_id


def _delete_with_retry(fn, timeout_s: float = 600.0) -> None:
    """Delete, retrying while ENIs a deleted PCS resource left behind still hold the VPC."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(15)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
