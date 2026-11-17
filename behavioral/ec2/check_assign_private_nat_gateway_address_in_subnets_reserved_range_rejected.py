"""assign-private-nat-gateway-address-in-subnets-reserved-range-rejected."""
from __future__ import annotations

import ipaddress
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "assign-private-nat-gateway-address-in-subnets-reserved-range-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssignPrivateNatGatewayAddress refuses one of the subnet's four AWS-reserved low
    addresses with the exact addresses named and adds nothing; an ordinary free address in the
    same subnet is accepted right after.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-natres-")

    vpc_id = _create_vpc_retrying(ec2, "10.219.0.0/24", name)
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_cidr = "10.219.0.0/25"
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

    network = ipaddress.ip_network(subnet_cidr)
    reserved_address = str(network.network_address + 1)

    code, message = _error_of(
        lambda: ec2.assign_private_nat_gateway_address(
            NatGatewayId=nat_id, PrivateIpAddresses=[reserved_address]
        )
    )
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r}: {message!r}"
    expected = (
        f"The provided private Ip addresses are in subnet's reserved address range [{reserved_address}]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unaffected = _addresses(ec2, nat_id)
    assert len(unaffected) == 1, (
        f"the refused assignment must leave only the primary address, got {unaffected!r}"
    )

    primary_ip = unaffected[0]["PrivateIp"]
    free_address = _first_free_host(subnet_cidr, exclude={primary_ip, reserved_address})
    ec2.assign_private_nat_gateway_address(NatGatewayId=nat_id, PrivateIpAddresses=[free_address])
    grown = _poll_until(
        lambda: _addresses(ec2, nat_id),
        lambda addrs: len(addrs) == 2 and all(a["Status"] == "succeeded" for a in addrs),
        timeout_s=180,
        interval_s=10,
    )
    grown_ips = {a["PrivateIp"] for a in grown}
    assert grown_ips == {primary_ip, free_address}, (
        f"an ordinary free address must be accepted right after the refusal, expected "
        f"{{{primary_ip!r}, {free_address!r}}}, got {grown_ips!r}"
    )


def _addresses(ec2, nat_id: str) -> list:
    return ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["NatGatewayAddresses"]


def _first_free_host(cidr: str, *, exclude: set) -> str:
    network = ipaddress.ip_network(cidr)
    reserved_low = 4
    for i, host in enumerate(network.hosts()):
        if i < reserved_low:
            continue
        if str(host) not in exclude:
            return str(host)
    raise AssertionError(f"no free host address found in {cidr!r} excluding {exclude!r}")


def _delete_nat_gateway(ec2, nat_id: str, *, timeout_s: float = 180.0, interval_s: float = 10.0) -> None:
    ec2.delete_nat_gateway(NatGatewayId=nat_id)
    _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"],
        lambda state: state == "deleted",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _error_of(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, value: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": value}]}


def _create_vpc_retrying(ec2, cidr: str, name: str, *, timeout_s: float = 180.0, interval_s: float = 10.0) -> str:
    """Create a VPC, retrying through a transient VpcLimitExceeded from sibling checks sharing the account."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return vpc_id


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
