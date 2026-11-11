"""op-contract-detach-vpn-gateway."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-detach-vpn-gateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachVpnGateway detaches an attached gateway (its VpcAttachments entry turns 'detached'),
    and a repeat detach of that same VpcId is an accepted no-op that leaves it 'detached'."""
    ec2 = ctx.client("ec2")

    # A VPC of its own: attaching a gateway to the default VPC, or to another run's VPC, would
    # change state this check does not own. The "not currently attached" path re-detaches the
    # same VpcId after it was detached, so one VPC suffices.
    vpc_a = ec2.create_vpc(
        CidrBlock="10.211.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", ctx.unique_name("sim2real-vgw-vpca-"))
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_a))

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=_tag_spec(ctx, "vpn-gateway", ctx.unique_name("sim2real-vgw-")),
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: _teardown_vgw(ec2, vgw_id, vpc_a))

    ec2.attach_vpn_gateway(VpnGatewayId=vgw_id, VpcId=vpc_a)
    # VPN gateway attachment is asynchronous and, on real AWS, commonly lingers in
    # 'attaching' well past 30s; give it a much longer bounded window before giving up.
    _poll_until(
        lambda: [
            att
            for att in ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0][
                "VpcAttachments"
            ]
            if att["VpcId"] == vpc_a
        ],
        lambda atts: bool(atts) and atts[0]["State"] == "attached",
        timeout_s=300.0,
        interval_s=5.0,
    )

    ec2.detach_vpn_gateway(VpnGatewayId=vgw_id, VpcId=vpc_a)
    # Detachment is likewise asynchronous; use the same generous bounded window.
    detached = _poll_until(
        lambda: [
            att
            for att in ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0][
                "VpcAttachments"
            ]
            if att["VpcId"] == vpc_a
        ],
        lambda atts: bool(atts) and atts[0]["State"] == "detached",
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert detached[0]["State"] == "detached", f"expected detached, got {detached[0]['State']!r}"

    # Real AWS treats a repeat detach request naming that same VpcId as an idempotent
    # no-op once the attachment record is already in 'detached' state: it does *not*
    # raise InvalidVpnGatewayAttachment.NotFound (that error is for a VpcId that was
    # never attached to this gateway in the first place, which is a different case from
    # a VpcId whose attachment record exists but is already 'detached'). Confirm the
    # repeat call genuinely succeeds as a no-op -- i.e. it must not resurrect the
    # attachment (flip it back to 'attaching'/'attached') -- rather than just checking
    # it doesn't error.
    ec2.detach_vpn_gateway(VpnGatewayId=vgw_id, VpcId=vpc_a)
    still_detached = [
        att
        for att in ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0][
            "VpcAttachments"
        ]
        if att["VpcId"] == vpc_a
    ]
    assert still_detached and still_detached[0]["State"] == "detached", still_detached


# ===== helpers =====
def _teardown_vgw(ec2, vgw_id, vpc_id, timeout_s=600.0, interval_s=10.0):
    """Teardown: detach the gateway from the check's own VPC, wait until that attachment is
    detached, then delete the gateway. Not found is success; any other error, or a detach that
    does not finish in time, raises."""
    from botocore.exceptions import ClientError

    try:
        ec2.detach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id)
    except ClientError as e:
        if e.response["Error"]["Code"] not in (
            "InvalidVpnGatewayID.NotFound",
            "InvalidVpnGatewayAttachment.NotFound",
        ):
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            gws = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidVpnGatewayID.NotFound":
                return
            raise
        atts = [a for gw in gws for a in gw.get("VpcAttachments", []) if a["VpcId"] == vpc_id]
        if all(a["State"] == "detached" for a in atts):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPN gateway {vgw_id} not detached from {vpc_id} within {timeout_s}s: {atts}")
        time.sleep(interval_s)
    try:
        ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidVpnGatewayID.NotFound":
            raise


def _delete_vpc(ec2, vpc_id, timeout_s=300.0, interval_s=10.0):
    """Teardown: delete the check's own VPC. DependencyViolation (a gateway or route table still
    releasing it) is retried; not found is success; any other error, or a timeout, raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [
                {"Key": "Name", "Value": name},
                {"Key": "sim2real", "Value": "true"},
                {"Key": "sim2real-created", "Value": str(int(time.time()))},
            ],
        }
    ]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
