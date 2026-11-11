"""op-contract-create-secondary-subnet."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-secondary-subnet"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSecondarySubnet: success creates a subnet within a secondary network's CIDR (an
    AvailabilityZone must be specified); a CIDR outside the parent network's range is rejected."""
    ec2 = ctx.client("ec2")
    net_name = ctx.unique_name("sim2real-behav-secnet-")
    subnet_name = ctx.unique_name("sim2real-behav-secsubnet-")

    net_resp = ec2.create_secondary_network(
        Ipv4CidrBlock="100.65.0.0/24",
        NetworkType="rdma",
        TagSpecifications=[
            {"ResourceType": "secondary-network", "Tags": [{"Key": "Name", "Value": net_name}]}
        ],
    )

    net_id = net_resp["SecondaryNetwork"]["SecondaryNetworkId"]
    ctx.on_cleanup(lambda: ec2.delete_secondary_network(SecondaryNetworkId=net_id))
    net_state = _poll_until(
        lambda: ec2.describe_secondary_networks(SecondaryNetworkIds=[net_id])[
            "SecondaryNetworks"
        ][0]["State"],
        lambda s: s in ("create-complete", "create-failed"),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"secondary network {net_id!r} reaching a terminal state",
    )
    assert net_state == "create-complete", f"secondary network ended in {net_state!r}"

    resp = ec2.create_secondary_subnet(
        SecondaryNetworkId=net_id,
        Ipv4CidrBlock="100.65.0.0/28",
        AvailabilityZone=_first_az(ctx),
        TagSpecifications=[
            {"ResourceType": "secondary-subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}
        ],
    )
    subnet = resp["SecondarySubnet"]
    subnet_id = subnet["SecondarySubnetId"]

    def _delete_subnet_and_wait():
        ec2.delete_secondary_subnet(SecondarySubnetId=subnet_id)
        _poll_until(
            lambda: ec2.describe_secondary_subnets(SecondarySubnetIds=[subnet_id])[
                "SecondarySubnets"
            ][0]["State"],
            lambda s: s in ("delete-complete", "delete-failed"),
            timeout_s=45.0,
            interval_s=3.0,
            description=f"secondary subnet {subnet_id!r} finishing delete",
        )

    # Registered LIFO after the network's own cleanup, so this (deleting and waiting for the
    # subnet to actually reach delete-complete) runs BEFORE the network delete below is attempted
    # -- DeleteSecondaryNetwork rejects a network that still has any secondary subnet, and the
    # subnet's own delete is asynchronous, so firing both deletes back-to-back leaks the network.
    ctx.on_cleanup(_delete_subnet_and_wait)

    assert subnet["SecondaryNetworkId"] == net_id, (
        f"created secondary subnet reports SecondaryNetworkId {subnet['SecondaryNetworkId']!r}, "
        f"expected {net_id!r}"
    )

    final_state = _poll_until(
        lambda: ec2.describe_secondary_subnets(SecondarySubnetIds=[subnet_id])[
            "SecondarySubnets"
        ][0]["State"],
        lambda s: s in ("create-complete", "create-failed"),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"secondary subnet {subnet_id!r} reaching a terminal state",
    )
    assert final_state == "create-complete", f"secondary subnet ended in {final_state!r}"

    # Error boundary: the requested CIDR is not within the parent secondary network's range.
    # Real AWS reports this as a dedicated range-conflict code, not the generic
    # InvalidParameterValue.
    outside_cidr = "10.0.0.0/28"
    code, message = _error(
        lambda: ec2.create_secondary_subnet(
            SecondaryNetworkId=net_id,
            Ipv4CidrBlock=outside_cidr,
            AvailabilityZone=_first_az(ctx),
        )
    )
    assert code == "InvalidSecondarySubnet.Range", (
        f"expected InvalidSecondarySubnet.Range, got {code!r}"
    )
    assert message == (
        f"The CIDR block '{outside_cidr}' is not contained within an IPv4 CIDR block "
        "in the specified secondary network."
    ), f"unexpected Range message: {message!r}"

    # Independent read at a different operation than the one that mutated: the rejected create
    # must not have disturbed the subnet that already exists on this network.
    recheck = ec2.describe_secondary_subnets(SecondarySubnetIds=[subnet_id])["SecondarySubnets"][0]
    assert recheck["SecondarySubnetId"] == subnet_id and recheck["State"] == "create-complete", (
        f"after the rejected CreateSecondarySubnet call, an independent read of {subnet_id!r} "
        f"returned id={recheck.get('SecondarySubnetId')!r} state={recheck.get('State')!r}, "
        f"expected id={subnet_id!r} state='create-complete'"
    )


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _first_az(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not zones:
        raise AssertionError("no available Availability Zone in this region")
    return zones[0]["ZoneName"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
