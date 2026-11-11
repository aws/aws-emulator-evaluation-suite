"""op-contract-assign-private-nat-gateway-address."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-assign-private-nat-gateway-address"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssignPrivateNatGatewayAddress adds a second distinct private IP to a private NAT gateway;
    an unknown NAT gateway id is rejected with NatGatewayNotFound."""
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _default_vpc_subnet(ctx)

    nat = ec2.create_nat_gateway(
        SubnetId=subnet_id,
        ConnectivityType="private",
        TagSpecifications=[
            {"ResourceType": "natgateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nat-")}]}
        ],
    )["NatGateway"]
    nat_id = nat["NatGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_nat_gateway(NatGatewayId=nat_id))

    _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"],
        lambda state: state == "available",
        timeout_s=300,
        interval_s=10,
    )

    before = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]
    before_count = len(before["NatGatewayAddresses"])
    assert before_count == 1, f"expected a single private IP before assignment, got {before_count}"

    resp = ec2.assign_private_nat_gateway_address(NatGatewayId=nat_id, PrivateIpAddressCount=1)
    assert resp["NatGatewayId"] == nat_id

    after_addrs = _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["NatGatewayAddresses"],
        lambda addrs: len(addrs) == 2 and all(a["Status"] == "succeeded" for a in addrs),
        timeout_s=180,
        interval_s=10,
    )
    private_ips = {a["PrivateIp"] for a in after_addrs}
    assert len(private_ips) == 2, f"expected 2 distinct private IPs, got {private_ips}"

    fake_nat_id = "nat-00000000000000000"
    code, message = _client_error(
        lambda: ec2.assign_private_nat_gateway_address(NatGatewayId=fake_nat_id, PrivateIpAddressCount=1)
    )
    assert code == "NatGatewayNotFound", f"unexpected error code: {code}"
    expected = f"The natgateway ID '{fake_nat_id}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Return the (code, message) of fn()'s ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _default_vpc_subnet(ctx):
    # A private NAT gateway needs no dedicated VPC; the shared network avoids the VPC quota.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return vpc_id, subnets[0]["SubnetId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
