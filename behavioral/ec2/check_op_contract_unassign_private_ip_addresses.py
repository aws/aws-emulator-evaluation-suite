"""op-contract-unassign-private-ip-addresses."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-unassign-private-ip-addresses"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnassignPrivateIpAddresses removes a secondary private IP from an ENI; unassigning the
    primary private IP address is rejected (immutable-field boundary)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-")
    tag = [{"Key": "Name", "Value": name}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.214.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ctx, vpc_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.214.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    eni = ec2.create_network_interface(
        SubnetId=subnet_id,
        Description="sim2real-behav",
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": tag}],
    )[
        "NetworkInterface"
    ]
    eni_id = eni["NetworkInterfaceId"]
    primary_ip = eni["PrivateIpAddress"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    ec2.assign_private_ip_addresses(NetworkInterfaceId=eni_id, SecondaryPrivateIpAddressCount=1)

    def private_ips():
        resp = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
        return [p["PrivateIpAddress"] for p in resp["NetworkInterfaces"][0]["PrivateIpAddresses"]]

    ips = _poll_until(private_ips, lambda ips: len(ips) == 2, timeout_s=30.0)
    secondary_ip = next(ip for ip in ips if ip != primary_ip)

    # success path: unassign the secondary and confirm removal
    ec2.unassign_private_ip_addresses(NetworkInterfaceId=eni_id, PrivateIpAddresses=[secondary_ip])
    remaining = _poll_until(private_ips, lambda ips: secondary_ip not in ips, timeout_s=30.0)
    assert secondary_ip not in remaining
    assert primary_ip in remaining

    # rejection boundary: the primary private IP address cannot be unassigned
    code, message = _error(
        lambda: ec2.unassign_private_ip_addresses(
            NetworkInterfaceId=eni_id, PrivateIpAddresses=[primary_ip]
        )
    )
    assert code == "InvalidParameterValue", code
    assert message == (
        f"Value ({primary_ip}) for parameter privateIpAddress is invalid. "
        "The primary IP address of an interface cannot be unassigned."
    ), f"unexpected InvalidParameterValue message {message!r}"

    # effect-absent: an independent read (describe, not unassign) proves the rejected call
    # left the primary IP attached rather than merely returning an error alongside a mutation
    after_reject = private_ips()
    assert primary_ip in after_reject, f"primary IP removed despite rejection: {after_reject}"
    assert after_reject == [primary_ip], f"unexpected IP set after rejection: {after_reject}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _wait_vpc_available(ctx, vpc_id, timeout_s=60.0):
    ec2 = ctx.client("ec2")

    def probe():
        resp = ec2.describe_vpcs(VpcIds=[vpc_id])
        return resp["Vpcs"][0]["State"]

    return _poll_until(probe, lambda s: s == "available", timeout_s=timeout_s, interval_s=2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
