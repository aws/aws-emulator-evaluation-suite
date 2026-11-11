"""trunk-interface-association-lifecycle."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "trunk-interface-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateTrunkInterface, DisassociateTrunkInterface and DescribeTrunkInterfaceAssociations, called by
    a principal without ENI trunking, each fail with OperationNotPermitted and the same exact message."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-trunk-")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    # Reuse the run's network rather than creating a new VPC: VPCs are a low
    # per-region quota.
    vpc_id = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"][0][
        "VpcId"
    ]

    subnet_id = _create_subnet_with_retry(ec2, vpc_id, az, name)
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))



    trunk = ec2.create_network_interface(
        SubnetId=subnet_id,
        InterfaceType="trunk",
        TagSpecifications=_tag_spec("network-interface", name + "-trunk"),
    )["NetworkInterface"]
    trunk_eni = trunk["NetworkInterfaceId"]
    # The refusal names the caller's account, which the interface reports as its owner.
    not_permitted = f"User {trunk['OwnerId']} is not permitted to perform this operation"
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=trunk_eni))

    branch_eni = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec("network-interface", name + "-branch"),
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=branch_eni))

    # AssociateTrunkInterface is reserved for the ECS/EKS ENI-trunking
    # controller; a normal IAM principal without an awsvpcTrunking-enabled
    # ECS container-instance role gets a specific rejection, not a generic
    # ValidationError and not a silent success.
    code, message = _error_code(
        lambda: ec2.associate_trunk_interface(
            TrunkInterfaceId=trunk_eni, BranchInterfaceId=branch_eni, VlanId=42
        )
    )
    assert code == "OperationNotPermitted", f"unexpected code: {code!r}"
    assert message == not_permitted, f"unexpected message: {message!r}"

    # DisassociateTrunkInterface against an association id that was never
    # created is gated by the same permission boundary -- it is rejected
    # with the identical OperationNotPermitted code (the principal is
    # stopped before any not-found check even runs), never a silent success.
    fake_assoc_id = "eni-attach-" + trunk_eni.split("-", 1)[1]
    dis_code, dis_message = _error_code(lambda: ec2.disassociate_trunk_interface(AssociationId=fake_assoc_id))
    assert dis_code == "OperationNotPermitted", f"unexpected code: {dis_code!r}"
    assert dis_message == not_permitted, f"unexpected message: {dis_message!r}"

    # Terminal, independent read at the destination: even after the associate
    # attempt above, describing by filter on the trunk interface is gated the
    # same way as Associate/Disassociate -- this whole API family requires the
    # ECS/EKS ENI-trunking controller principal, not a normal IAM principal --
    # so there is no association visible, and none could have been created by
    # the rejected associate call.
    describe_code, describe_message = _error_code(
        lambda: ec2.describe_trunk_interface_associations(
            Filters=[{"Name": "trunk-interface-association.trunk-interface-id", "Values": [trunk_eni]}]
        )
    )
    assert describe_code == "OperationNotPermitted", f"unexpected code: {describe_code!r}"
    assert describe_message == not_permitted, f"unexpected message: {describe_message!r}"



def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _pick_free_subnet_cidr(ec2, vpc_id: str, new_prefix: int = 24) -> str:
    """Finds an unused /new_prefix CIDR inside vpc_id's CIDR block(s) that
    does not overlap any existing subnet -- avoids needing to create a brand
    new VPC (a scarce, tightly-quota-limited resource) just to get a subnet."""
    import ipaddress

    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    vpc_cidrs = [a["CidrBlock"] for a in vpc.get("CidrBlockAssociationSet", []) if a.get("CidrBlock")]
    if not vpc_cidrs:
        vpc_cidrs = [vpc["CidrBlock"]]

    existing = [
        ipaddress.ip_network(s["CidrBlock"])
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    ]

    for vpc_cidr in vpc_cidrs:
        vpc_net = ipaddress.ip_network(vpc_cidr)
        if vpc_net.prefixlen > new_prefix:
            continue
        for candidate in vpc_net.subnets(new_prefix=new_prefix):
            if not any(candidate.overlaps(existing_net) for existing_net in existing):
                return str(candidate)
    raise AssertionError(f"no free /{new_prefix} CIDR found in VPC {vpc_id}")


def _create_subnet_with_retry(ec2, vpc_id: str, az: str, name: str, attempts: int = 6):
    """Picking a free CIDR and creating the subnet is not atomic, so a
    concurrent check on the same shared default VPC can race us for the
    same candidate CIDR (InvalidSubnet.Conflict). Recompute and retry."""
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        cidr = _pick_free_subnet_cidr(ec2, vpc_id)
        try:
            return ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=cidr,
                AvailabilityZone=az,
                TagSpecifications=_tag_spec("subnet", name),
            )["Subnet"]["SubnetId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSubnet.Conflict":
                raise
            last_exc = exc
    raise last_exc




def _error_code(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a target
    that accepts a call real AWS rejects is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
