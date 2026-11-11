"""create-network-interface."""
from __future__ import annotations

import ipaddress

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-interface"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkInterface in a /28 subnet of the run's network gets a private IP inside the subnet and its Name
    tag, while asking for more secondary IPs than are free is refused with InsufficientFreeAddressesInSubnet
    and its exact message and leaves no partial ENI.
    """
    ec2 = ctx.client("ec2")
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    cidr = _pick_free_subnet_cidr(ec2, vpc_id, prefix_len=28)
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr)["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    name = ctx.unique_name("sim2real-behav-eni-")
    eni = ec2.create_network_interface(
        SubnetId=subnet_id,
        Description="sim2real behavioral check",
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": name}]}],
    )["NetworkInterface"]
    eni_id = eni["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    # Independent read at the destination: the create response alone would also satisfy a
    # stub that just echoes its own input back.
    described = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    assert described["SubnetId"] == subnet_id, f"expected subnet {subnet_id!r}, got {described['SubnetId']!r}"
    assert described["VpcId"] == vpc_id, f"expected vpc {vpc_id!r}, got {described['VpcId']!r}"
    assert ipaddress.ip_address(described["PrivateIpAddress"]) in ipaddress.ip_network(cidr), (
        f"assigned private IP {described['PrivateIpAddress']} falls outside subnet CIDR {cidr}"
    )
    tag_map = {t["Key"]: t["Value"] for t in described.get("TagSet", [])}
    assert tag_map.get("Name") == name, f"expected Name tag {name!r}, got {tag_map.get('Name')!r}"

    code, message = _error(
        lambda: ec2.create_network_interface(SubnetId=subnet_id, SecondaryPrivateIpAddressCount=20)
    )
    assert code == "InsufficientFreeAddressesInSubnet", (
        f"expected InsufficientFreeAddressesInSubnet, got {code!r}"
    )
    assert message == ("The specified subnet does not have enough free addresses to satisfy the "
                       "request."), message

    # Absent-effect beat: the rejected call must not have left a partial ENI behind.
    survivors = ec2.describe_network_interfaces(
        Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
    )["NetworkInterfaces"]
    survivor_ids = [e["NetworkInterfaceId"] for e in survivors]
    assert survivor_ids == [eni_id], (
        f"rejected CreateNetworkInterface must not create a partial ENI; found {survivor_ids} in {subnet_id}"
    )


def _error(fn):
    """Call fn(); return its (code, message). ParamValidationError means the request never left the
    SDK, so it is never a valid stand-in for a server-side rejection; an unexpected SUCCESS raises
    rather than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        return vpcs[0]["VpcId"]
    raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")


def _pick_free_subnet_cidr(ec2, vpc_id, prefix_len=28):
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    associations = [
        a for a in vpc.get("CidrBlockAssociationSet", [])
        if a.get("CidrBlockState", {}).get("State") == "associated"
    ]
    vpc_nets = [ipaddress.ip_network(a["CidrBlock"]) for a in associations] or [
        ipaddress.ip_network(vpc["CidrBlock"])
    ]
    existing = [
        ipaddress.ip_network(s["CidrBlock"])
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    ]
    for vpc_net in vpc_nets:
        if vpc_net.prefixlen > prefix_len:
            continue
        for candidate in vpc_net.subnets(new_prefix=prefix_len):
            if not any(candidate.overlaps(e) for e in existing):
                return str(candidate)
    raise RuntimeError(f"no free /{prefix_len} CIDR block found in VPC {vpc_id}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
