"""op-contract-enable-vgw-route-propagation."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-enable-vgw-route-propagation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableVgwRoutePropagation adds the VGW to a route table's PropagatingVgws,
    and rejects a route table id that doesn't exist with the documented NotFound code."""
    ec2 = ctx.client("ec2")

    # The check attaches a VGW and adds a route table, so it uses a VPC of its own.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_for(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available")

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt_id))

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=[{"ResourceType": "vpn-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["VpnGateway"]["VpnGatewayId"]

    def _cleanup_vgw() -> None:
        from botocore.exceptions import ClientError
        deadline = time.monotonic() + 300
        while True:
            try:
                ec2.detach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id)
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                # Never attached (the attach call failed) or already detached.
                if code in ("InvalidVpnGatewayAttachment.NotFound", "IncorrectState"):
                    break
                # An attach still in progress refuses the detach ("conflicting pending workflow").
                if code != "InvalidParameterValue" or time.monotonic() >= deadline:
                    raise
            time.sleep(10)
        _wait_for(lambda: _vgw_detached(ec2, vgw_id), timeout_s=400, interval_s=10)
        ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)

    ctx.on_cleanup(_cleanup_vgw)

    ec2.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id)
    # A VGW attachment takes several minutes on real AWS.
    _wait_for(lambda: _vgw_attached(ec2, vgw_id, vpc_id), timeout_s=900, interval_s=10)

    # --- success path: propagation is recorded on the route table ---
    resp = ec2.enable_vgw_route_propagation(RouteTableId=rt_id, GatewayId=vgw_id)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from EnableVgwRoutePropagation, got {status}"
    ctx.on_cleanup(lambda: _safe_disable(ec2, rt_id, vgw_id))

    rt = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]
    propagating = [p["GatewayId"] for p in rt.get("PropagatingVgws", [])]
    assert vgw_id in propagating, f"expected {vgw_id} in PropagatingVgws, got {propagating}"

    # --- error boundary: nonexistent route table id ---
    code, message = _client_error(lambda: ec2.enable_vgw_route_propagation(
        RouteTableId="rtb-00000000000000000", GatewayId=vgw_id
    ))
    assert code == "InvalidRouteTableID.NotFound", code
    expected_message = "The routeTable ID 'rtb-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _safe_disable(ec2: Any, rt_id: str, vgw_id: str) -> None:
    from botocore.exceptions import ClientError
    try:
        ec2.disable_vgw_route_propagation(RouteTableId=rt_id, GatewayId=vgw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidRouteTableID.NotFound", "Gateway.NotAttached"):
            raise


def _vgw_attached(ec2: Any, vgw_id: str, vpc_id: str) -> bool:
    vgw = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]
    for att in vgw.get("VpcAttachments", []):
        if att["VpcId"] == vpc_id and att["State"] == "attached":
            return True
    return False


def _vgw_detached(ec2: Any, vgw_id: str) -> bool:
    vgw = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]
    for att in vgw.get("VpcAttachments", []):
        if att["State"] not in ("detached",):
            return False
    return True


def _wait_for(predicate: Callable[[], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError("condition not met within timeout")


def _client_error(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
