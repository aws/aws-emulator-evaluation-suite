"""op-contract-unassign-ipv6-addresses."""
from __future__ import annotations

import ipaddress
import time

from behavioral_harness import tags

CHECK = "op-contract-unassign-ipv6-addresses"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnassignIpv6Addresses removes a previously-assigned IPv6 address from an ENI; bogus
    ENI id -> NotFound."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": "1"}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.213.0.0/16",
        AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ipv6_cidr = _wait_vpc_ipv6_cidr(ctx, vpc_id)

    subnet_ipv6 = str(next(ipaddress.ip_network(ipv6_cidr).subnets(new_prefix=64)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.213.1.0/24",
        Ipv6CidrBlock=subnet_ipv6,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        Description="sim2real-behav",
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": tag}],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    assigned = ec2.assign_ipv6_addresses(NetworkInterfaceId=eni_id, Ipv6AddressCount=1)
    addresses = assigned["AssignedIpv6Addresses"]
    assert len(addresses) == 1, f"expected 1 assigned address, got {addresses!r}"
    address = addresses[0]

    def eni_ipv6_addresses():
        resp = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
        return [a["Ipv6Address"] for a in resp["NetworkInterfaces"][0].get("Ipv6Addresses", [])]

    found = _poll_until(eni_ipv6_addresses, lambda a: address in a, timeout_s=30.0)
    assert address in found, f"expected {address} visible on ENI, got {found!r}"

    # success path: unassign it and confirm removal
    ec2.unassign_ipv6_addresses(NetworkInterfaceId=eni_id, Ipv6Addresses=[address])
    remaining = _poll_until(eni_ipv6_addresses, lambda a: address not in a, timeout_s=30.0)
    assert address not in remaining, f"expected {address} removed, still present in {remaining!r}"

    # error boundary: nonexistent network interface id
    code, message = _error_code(
        lambda: ec2.unassign_ipv6_addresses(
            NetworkInterfaceId="eni-00000000000000000", Ipv6Addresses=[address]
        )
    )
    assert code == "InvalidNetworkInterfaceID.NotFound", code
    assert message == "The interface ID 'eni-00000000000000000' does not exist", message


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError, call succeeded")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _wait_vpc_ipv6_cidr(ctx, vpc_id, timeout_s=60.0):
    ec2 = ctx.client("ec2")

    def probe():
        resp = ec2.describe_vpcs(VpcIds=[vpc_id])
        assocs = resp["Vpcs"][0].get("Ipv6CidrBlockAssociationSet", [])
        for a in assocs:
            if a.get("Ipv6CidrBlockState", {}).get("State") == "associated":
                return a["Ipv6CidrBlock"]
        return None

    return _poll_until(probe, lambda c: c is not None, timeout_s=timeout_s, interval_s=2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
