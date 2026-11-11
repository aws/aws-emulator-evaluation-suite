"""op-contract-disassociate-address."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disassociate-address"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateAddress with DryRun answers DryRunOperation and keeps the association; the real call
    removes the Elastic IP's association, and repeating it fails with InvalidAssociationID.NotFound
    (exact messages) with the address left unassociated."""
    ec2 = ctx.client("ec2")

    # Use the network's existing VPC and subnet: CreateVpc has a low per-account limit, and
    # AssociateAddress only needs a VPC-domain ENI, with no internet gateway.
    vpc_id, subnet_id = _pick_default_vpc_and_subnet(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_id = _create_with_retry(
            lambda: ec2.create_vpc(
                CidrBlock="10.75.0.0/16",
                TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
            )["Vpc"]["VpcId"],
            retry_codes=("VpcLimitExceeded",),
            timeout_s=300.0,
            interval_s=15.0,
        )
        ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    if subnet_id is None:
        az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.75.1.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id)))

    alloc_id = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["AllocationId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.release_address(AllocationId=alloc_id)))

    assoc_id = ec2.associate_address(AllocationId=alloc_id, NetworkInterfaceId=eni_id)["AssociationId"]

    described = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
    assert described.get("AssociationId") == assoc_id, described

    # Error boundary: DryRun must report DryRunOperation without disassociating.
    code, message = _client_error(lambda: ec2.disassociate_address(AssociationId=assoc_id, DryRun=True))
    assert code == "DryRunOperation", code
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    still = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
    assert still.get("AssociationId") == assoc_id, still

    # DisassociateAddress has no response members for a VPC-domain EIP (no
    # "Return" key on real AWS) — the operation's contract is verified via the
    # resulting resource state, not the (empty) response body.
    resp = ec2.disassociate_address(AssociationId=assoc_id)
    assert isinstance(resp, dict), resp

    after = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
    assert "AssociationId" not in after, after

    # Repeating the disassociate with the same association ID fails with
    # InvalidAssociationID.NotFound (the call is not idempotent), and the address stays unassociated.
    resp2_code, resp2_message = _client_error(lambda: ec2.disassociate_address(AssociationId=assoc_id))
    assert resp2_code == "InvalidAssociationID.NotFound", resp2_code
    assert resp2_message == f"The association ID '{assoc_id}' does not exist", (
        f"unexpected InvalidAssociationID.NotFound message: {resp2_message!r}"
    )
    after2 = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
    assert "AssociationId" not in after2, after2


def _pick_default_vpc_and_subnet(ec2, *, ctx):
    """Prefer the account's existing shared network (and one of its
    already-provisioned subnets) over allocating a brand-new VPC — the
    shared network costs nothing against the per-account VPC limit and already
    has a usable subnet for hosting the test ENI."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        return vpc_id, None
    subnet = max(subnets, key=lambda s: s.get("AvailableIpAddressCount", 0))
    return vpc_id, subnet["SubnetId"]


def _create_with_retry(fn, retry_codes, timeout_s=150.0, interval_s=20.0):
    """Retry a create-style call while the account is transiently at a
    resource-limit ceiling (shared quota contention with other concurrently
    running checks); re-raise once the timeout is exhausted or the error is
    not one of the expected transient limit codes."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAllocationID.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidSubnetID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
