"""op-contract-unassign-private-nat-gateway-address."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-unassign-private-nat-gateway-address"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnassignPrivateNatGatewayAddress removes a secondary private IP from a private NAT gateway;
    unassigning the primary IP is rejected with InvalidParameter and leaves it in place."""
    ec2 = ctx.client("ec2")

    # Reuse the shared network: the VPC quota is small, so a new VPC risks VpcLimitExceeded.
    vpc_id, subnet_ids = _default_vpc_subnets(ec2, count=1, ctx=ctx)
    subnet_id = subnet_ids[0]

    nat_id = ec2.create_nat_gateway(
        SubnetId=subnet_id,
        ConnectivityType="private",
        TagSpecifications=[
            {
                "ResourceType": "natgateway",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-nat-")}],
            }
        ],
    )["NatGateway"]["NatGatewayId"]

    def _cleanup_nat():
        try:
            ec2.delete_nat_gateway(NatGatewayId=nat_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NatGatewayNotFound":
                raise

    ctx.on_cleanup(_cleanup_nat)
    _wait_nat_state(ctx, nat_id, {"available"})

    def addresses():
        resp = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])
        return resp["NatGateways"][0]["NatGatewayAddresses"]

    initial = addresses()
    assert len(initial) == 1
    primary_ip = initial[0]["PrivateIp"]

    ec2.assign_private_nat_gateway_address(NatGatewayId=nat_id, PrivateIpAddressCount=1)

    def _grown_with_distinct_ips(a):
        # Right after assignment the new entry's PrivateIp can be unpopulated or duplicate
        # the primary, so wait for two distinct populated addresses.
        if len(a) != 2:
            return False
        ips = {addr.get("PrivateIp") for addr in a}
        return len(ips) == 2 and all(ips)

    grown = _poll_until(addresses, _grown_with_distinct_ips, timeout_s=60.0)
    secondary_ip = next(a["PrivateIp"] for a in grown if a["PrivateIp"] != primary_ip)

    ec2.unassign_private_nat_gateway_address(
        NatGatewayId=nat_id, PrivateIpAddresses=[secondary_ip], MaxDrainDurationSeconds=1
    )
    shrunk = _poll_until(addresses, lambda a: len(a) == 1, timeout_s=90.0)
    assert shrunk[0]["PrivateIp"] == primary_ip

    code, message = _error(
        lambda: ec2.unassign_private_nat_gateway_address(
            NatGatewayId=nat_id, PrivateIpAddresses=[primary_ip]
        )
    )
    expected = (
        "InvalidParameter",
        f"Private IP address {primary_ip} is primary private IP of NAT, "
        "unassigning primary IP is not supported.",
    )
    assert (code, message) == expected, f"expected {expected!r}, got {(code, message)!r}"

    still_present = addresses()
    assert len(still_present) == 1 and still_present[0]["PrivateIp"] == primary_ip, (
        f"rejected unassign must leave exactly the primary IP in place, got {still_present}"
    )


def _default_vpc_subnets(ec2, count=1, *, ctx):
    """Return (vpc_id, subnet_ids) from the shared network, one subnet per distinct AZ."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "no shared network VPC available in this account/region"
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    seen_azs = set()
    subnet_ids = []
    for s in subnets:
        if s["AvailabilityZone"] in seen_azs:
            continue
        seen_azs.add(s["AvailabilityZone"])
        subnet_ids.append(s["SubnetId"])
        if len(subnet_ids) == count:
            break
    assert len(subnet_ids) >= count, f"need {count} network subnets in distinct AZs, found {subnet_ids}"
    return vpc_id, subnet_ids


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _wait_nat_state(ctx, nat_id, states, timeout_s=180.0):
    ec2 = ctx.client("ec2")

    def probe():
        resp = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])
        return resp["NatGateways"][0]["State"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s, interval_s=5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
