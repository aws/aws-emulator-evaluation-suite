"""op-contract-associate-nat-gateway-address."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-associate-nat-gateway-address"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateNatGatewayAddress adds a secondary Elastic IP to a public NAT gateway; a
    nonexistent NAT gateway id is rejected (NatGatewayNotFound)."""
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _default_vpc_subnet(ctx)

    primary_eip = ec2.allocate_address(Domain="vpc")
    primary_alloc_id = primary_eip["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=primary_alloc_id))
    # Allocated before the NAT gateway so LIFO cleanup releases it only after the gateway is
    # deleted; a held address cannot be released.
    second_eip = ec2.allocate_address(Domain="vpc")
    second_alloc_id = second_eip["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=second_alloc_id))

    nat = ec2.create_nat_gateway(
        SubnetId=subnet_id,
        ConnectivityType="public",
        AllocationId=primary_alloc_id,
        TagSpecifications=[
            {"ResourceType": "natgateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nat-")}]}
        ],
    )["NatGateway"]
    nat_id = nat["NatGatewayId"]
    ctx.on_cleanup(lambda: _delete_nat_gateway_and_wait(ec2, nat_id))

    _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"],
        lambda state: state == "available",
        timeout_s=300,
        interval_s=10,
    )

    resp = ec2.associate_nat_gateway_address(NatGatewayId=nat_id, AllocationIds=[second_alloc_id])
    assert resp["NatGatewayId"] == nat_id, f"expected {nat_id}, got {resp['NatGatewayId']}"
    addrs = _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["NatGatewayAddresses"],
        lambda addrs: len(addrs) == 2 and all(a["Status"] == "succeeded" for a in addrs),
        timeout_s=180,
        interval_s=10,
    )
    alloc_ids = {a["AllocationId"] for a in addrs}
    assert alloc_ids == {primary_alloc_id, second_alloc_id}, f"unexpected allocations: {alloc_ids}"

    fake_nat_id = "nat-00000000000000000"
    code, message = _client_error(
        lambda: ec2.associate_nat_gateway_address(NatGatewayId=fake_nat_id, AllocationIds=[second_alloc_id])
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


def _delete_nat_gateway_and_wait(ec2, nat_id, timeout_s: float = 600.0):
    """Delete the NAT gateway and wait for `deleted`, so the addresses it holds can be released."""
    ec2.delete_nat_gateway(NatGatewayId=nat_id)
    _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"],
        lambda state: state in ("deleted", "failed"),
        timeout_s=timeout_s,
        interval_s=10,
    )


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
    # The shared network already has an attached internet gateway, as a public NAT gateway needs.
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
