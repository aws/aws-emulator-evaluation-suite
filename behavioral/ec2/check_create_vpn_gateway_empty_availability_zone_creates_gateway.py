"""create-vpn-gateway-empty-availability-zone-creates-gateway."""

from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-vpn-gateway-empty-availability-zone-creates-gateway"
GROUP = "vpn-gateway"
SERVICES = ["ec2"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateVpnGateway refuses an unknown zone name and creates nothing.

    With AvailabilityZone '' it creates an ipsec.1 gateway: available, no zone, default ASN.
    """
    ec2 = ctx.client("ec2")
    marker = ctx.unique_name("sim2real-vgw-")

    def create(az):
        gateway = ec2.create_vpn_gateway(
            Type="ipsec.1",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "vpn-gateway", "Tags": _tags_for(marker)}],
        )["VpnGateway"]
        vgw_id = gateway["VpnGatewayId"]
        ctx.on_cleanup(lambda: _delete_vgw(ec2, vgw_id))
        return gateway

    zone_names = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "region-name", "Values": [ctx.region]}]
        )["AvailabilityZones"]
    }

    bad_az = f"{ctx.region}-nozone"
    code, message = _error(lambda: create(bad_az))
    # The supported zone list depends on the account's zones: the literal text is pinned around
    # it and the listed names are graded by membership.
    zones = re.search(r"zones: ([a-z0-9,-]+)\.$", message or "")
    listed = zones.group(1).split(",") if zones else []
    shaped = re.sub(r"zones: [a-z0-9,-]+\.$", "zones: <zones>.", message or "")
    want = (
        "InvalidParameterValue",
        f"Value ({bad_az}) for parameter availabilityZone is invalid. VpnConnection gateways "
        "can currently only be created in the following availability zones: <zones>.",
    )
    assert (code, shaped) == want, (
        f"CreateVpnGateway AvailabilityZone {bad_az!r}: expected {want!r}, got {(code, message)!r}"
    )
    assert listed and len(listed) == len(set(listed)) and set(listed) <= zone_names, (
        f"the refusal must list distinct zones of {ctx.region}: {listed!r}, {sorted(zone_names)!r}"
    )
    assert _by_marker(ec2, marker) == [], (
        f"the refused create must leave no gateway, got {_by_marker(ec2, marker)!r}"
    )

    created = create("")
    vgw_id = created["VpnGatewayId"]
    final = _poll(
        lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0],
        lambda g: g["State"] != "pending",
        timeout_s=120.0,
    )
    got = {
        "State": final["State"],
        "Type": final["Type"],
        "AmazonSideAsn": final["AmazonSideAsn"],
        "VpcAttachments": final["VpcAttachments"],
        "HasAvailabilityZone": "AvailabilityZone" in final,
        "Tags": {t["Key"]: t["Value"] for t in final.get("Tags", [])},
    }
    want_gateway = {
        "State": "available",
        "Type": "ipsec.1",
        "AmazonSideAsn": 64512,
        "VpcAttachments": [],
        "HasAvailabilityZone": False,
        "Tags": {t["Key"]: t["Value"] for t in _tags_for(marker)},
    }
    assert got == want_gateway, (
        f"DescribeVpnGateways {vgw_id!r}: expected {want_gateway!r}, got {got!r}"
    )
    assert _by_marker(ec2, marker) == [vgw_id], (
        f"exactly the one created gateway carries the marker, got {_by_marker(ec2, marker)!r}"
    )


def _by_marker(ec2, marker):
    found = ec2.describe_vpn_gateways(
        Filters=[{"Name": "tag:sim2real-marker", "Values": [marker]}]
    )["VpnGateways"]
    return sorted(g["VpnGatewayId"] for g in found if g["State"] != "deleted")


def _tags_for(marker):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-marker", "Value": marker}]


def _error(fn):
    """Return the (code, message) fn() is refused with; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _vgw_state(ec2, vgw_id):
    try:
        found = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpnGatewayID.NotFound":
            raise
        return "deleted"
    return found[0]["State"] if found else "deleted"


def _delete_vgw(ec2, vgw_id):
    """Delete the gateway and poll until it describes as deleted; a failed delete raises."""
    try:
        ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpnGatewayID.NotFound":
            raise
        return
    _poll(lambda: _vgw_state(ec2, vgw_id), lambda s: s == "deleted", timeout_s=300.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
