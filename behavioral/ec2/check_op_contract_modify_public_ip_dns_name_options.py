"""op-contract-modify-public-ip-dns-name-options."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-public-ip-dns-name-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyPublicIpDnsNameOptions: a valid network interface accepts a hostname-type
    change, and a nonexistent network interface id is rejected."""
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx)

    name = ctx.unique_name("sim2real-behav-eni-")
    eni = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec("network-interface", name)]
    )["NetworkInterface"]
    eni_id = eni["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    # Requesting the "public-ipv4-dns-name" hostname type requires the network
    # interface to actually have a public IPv4 address (real AWS rejects it
    # otherwise with "Provided interface must contain an ipv4 address"), so
    # allocate and associate an Elastic IP with the ENI first.
    try:
        allocation = ec2.allocate_address(Domain="vpc")
    except Exception as e:
        raise AssertionError(f"could not allocate an Elastic IP address: {e}")
    allocation_id = allocation["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))
    association = ec2.associate_address(AllocationId=allocation_id, NetworkInterfaceId=eni_id)
    association_id = association.get("AssociationId")
    if association_id:
        ctx.on_cleanup(lambda: ec2.disassociate_address(AssociationId=association_id))

    # success path
    resp = ec2.modify_public_ip_dns_name_options(
        NetworkInterfaceId=eni_id, HostnameType="public-ipv4-dns-name"
    )
    assert resp["Successful"] is True, resp

    # independent terminal read: confirm the setting actually stuck, through
    # DescribeNetworkInterfaces rather than the mutating call's own response.
    described = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    dns_opts = described.get("PublicIpDnsNameOptions", {})
    assert dns_opts.get("DnsHostnameType") == "public-ipv4-dns-name", dns_opts

    # error boundary. Real AWS validates the network interface id format for this
    # operation before doing an existence lookup, so an all-zero placeholder id
    # (which never corresponds to a real ENI) is rejected as malformed rather than
    # "not found".
    err, err_message = _client_error(
        lambda: ec2.modify_public_ip_dns_name_options(
            NetworkInterfaceId="eni-00000000000000000", HostnameType="public-ipv4-dns-name"
        )
    )
    assert err == "InvalidNetworkInterfaceId.Malformed", err
    expected_message = "The network-interface ID 'eni-00000000000000000' is malformed"
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_and_subnet(ctx):
    # Prefer reusing an existing VPC/subnet (e.g. the run's shared network) to avoid
    # tripping the per-account VpcLimitExceeded quota; only create a fresh VPC/subnet
    # if nothing reusable is available.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        for subnet in subnets:
            if subnet.get("AvailableIpAddressCount", 0) > 0:
                return vpc["VpcId"], subnet["SubnetId"]

    name = ctx.unique_name("sim2real-behav-net-")
    vpc = ec2.create_vpc(CidrBlock="10.80.0.0/24", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.80.0.0/28", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
