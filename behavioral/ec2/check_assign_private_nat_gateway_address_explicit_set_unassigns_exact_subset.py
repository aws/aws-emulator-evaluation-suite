"""assign-private-nat-gateway-address-explicit-set-unassigns-exact-subset."""
from __future__ import annotations

import ipaddress
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "assign-private-nat-gateway-address-explicit-set-unassigns-exact-subset"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssignPrivateNatGatewayAddress with two explicit addresses grows a private NAT gateway to
    exactly its primary plus both named addresses; unassigning one of them by address leaves
    exactly the other two, never the whole set.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-natexp-")

    vpc_id = _create_vpc_retrying(ec2, "10.216.0.0/24", name)
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    subnet_cidr = "10.216.0.0/25"
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    nat_id = ec2.create_nat_gateway(
        SubnetId=subnet_id,
        ConnectivityType="private",
        TagSpecifications=[_tag_spec("natgateway", name)],
    )["NatGateway"]["NatGatewayId"]
    ctx.on_cleanup(lambda: _delete_nat_gateway(ec2, nat_id))
    _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"],
        lambda state: state == "available",
        timeout_s=300,
        interval_s=10,
    )

    primary_ip = _addresses(ec2, nat_id)[0]["PrivateIp"]
    extra_a, extra_b = _two_free_hosts(subnet_cidr, exclude={primary_ip})

    ec2.assign_private_nat_gateway_address(
        NatGatewayId=nat_id, PrivateIpAddresses=[extra_a, extra_b]
    )
    grown = _poll_until(
        lambda: _addresses(ec2, nat_id),
        lambda addrs: len(addrs) == 3 and all(a["Status"] == "succeeded" for a in addrs),
        timeout_s=180,
        interval_s=10,
    )
    grown_ips = {a["PrivateIp"] for a in grown}
    assert grown_ips == {primary_ip, extra_a, extra_b}, (
        f"expected exactly {{{primary_ip!r}, {extra_a!r}, {extra_b!r}}} after assigning both "
        f"explicit addresses, got {grown_ips!r}"
    )

    ec2.unassign_private_nat_gateway_address(
        NatGatewayId=nat_id, PrivateIpAddresses=[extra_a], MaxDrainDurationSeconds=1
    )
    shrunk = _poll_until(
        lambda: _addresses(ec2, nat_id),
        lambda addrs: len(addrs) == 2,
        timeout_s=120,
        interval_s=10,
    )
    shrunk_ips = {a["PrivateIp"] for a in shrunk}
    assert shrunk_ips == {primary_ip, extra_b}, (
        f"unassigning {extra_a!r} alone must leave exactly {{{primary_ip!r}, {extra_b!r}}}, "
        f"got {shrunk_ips!r}"
    )


def _addresses(ec2, nat_id: str) -> list:
    return ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["NatGatewayAddresses"]


def _two_free_hosts(cidr: str, *, exclude: set) -> tuple[str, str]:
    """Two usable host addresses of ``cidr``, skipping AWS's four reserved low addresses
    (network, VPC router, DNS, future-use) and anything already in ``exclude``."""
    network = ipaddress.ip_network(cidr)
    reserved_low = 4
    hosts = (
        str(h)
        for i, h in enumerate(network.hosts())
        if i >= reserved_low and str(h) not in exclude
    )
    return next(hosts), next(hosts)


def _delete_nat_gateway(ec2, nat_id: str, *, timeout_s: float = 180.0, interval_s: float = 10.0) -> None:
    """Delete the NAT gateway and wait for it to clear so a dependent subnet/VPC delete can follow."""
    ec2.delete_nat_gateway(NatGatewayId=nat_id)
    _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"],
        lambda state: state == "deleted",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _tag_spec(resource_type: str, value: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": value}]}


def _create_vpc_retrying(ec2, cidr: str, name: str, *, timeout_s: float = 180.0, interval_s: float = 10.0) -> str:
    """Create a VPC, retrying through a transient VpcLimitExceeded from sibling checks sharing the account."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
