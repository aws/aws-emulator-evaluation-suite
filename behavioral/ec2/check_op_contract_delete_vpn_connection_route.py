"""op-contract-deleteVpnConnectionRoute."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpnConnectionRoute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpnConnectionRoute removes a static route; deleting it again is rejected InvalidRoute.NotFound."""
    ec2 = ctx.client("ec2")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65001,
        PublicIp="203.0.113.77",
        Type="ipsec.1",
        TagSpecifications=[_tag_spec(ctx, "customer-gateway", "cgw-route")],
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: _retry_in_use(ec2, lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))))

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1", TagSpecifications=[_tag_spec(ctx, "vpn-gateway", "vgw-route")]
    )["VpnGateway"]["VpnGatewayId"]
    # DeleteVpnGateway answers IncorrectState while the VPN connection is still deleting.
    ctx.on_cleanup(lambda: _safe(lambda: _retry_in_use(ec2, lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id))))

    # the gateway must be describable/available before it can be referenced by CreateVpnConnection
    _poll_until(
        lambda: _vgw_state(ec2, vgw_id),
        lambda s: s == "available",
        timeout_s=60.0,
    )

    vpn_id = ec2.create_vpn_connection(
        Type="ipsec.1",
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        Options={"StaticRoutesOnly": True},
        TagSpecifications=[_tag_spec(ctx, "vpn-connection", "vpn-route")],
    )["VpnConnection"]["VpnConnectionId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpn_connection(VpnConnectionId=vpn_id)))

    destination_cidr = "172.31.0.0/24"
    ec2.create_vpn_connection_route(VpnConnectionId=vpn_id, DestinationCidrBlock=destination_cidr)

    def _routes():
        return ec2.describe_vpn_connections(VpnConnectionIds=[vpn_id])["VpnConnections"][0]["Routes"]

    routes = _routes()
    assert any(r["DestinationCidrBlock"] == destination_cidr for r in routes), (
        f"expected the created static route to appear, got {routes!r}"
    )

    # success path: delete the static route
    ec2.delete_vpn_connection_route(VpnConnectionId=vpn_id, DestinationCidrBlock=destination_cidr)

    # real AWS keeps a Routes entry for the deleted CIDR around with State="deleted"
    # rather than removing it from the list outright, so "gone" means no *active* route
    # with that destination remains, not that the entry disappears entirely
    def _route_is_gone(rs):
        return not any(
            r["DestinationCidrBlock"] == destination_cidr and r.get("State") != "deleted" for r in rs
        )

    routes_after = _poll_until(
        _routes,
        _route_is_gone,
        timeout_s=60.0,
    )
    assert _route_is_gone(routes_after), (
        f"expected the route to be gone (or marked deleted) after delete, got {routes_after!r}"
    )

    # distinct error boundary: deleting a route that was never created is rejected.
    # real AWS keeps the just-deleted CIDR's Routes entry around (State="deleted", per
    # above), and re-issuing DeleteVpnConnectionRoute against that still-tracked,
    # already-deleted CIDR is treated as a no-op success rather than an error -- so
    # exercise the NotFound boundary with a genuinely never-created destination instead.
    never_created_cidr = "172.31.9.0/24"
    code, message = _error_of(
        lambda: ec2.delete_vpn_connection_route(VpnConnectionId=vpn_id, DestinationCidrBlock=never_created_cidr)
    )
    assert code == "InvalidRoute.NotFound", f"expected InvalidRoute.NotFound, got {code!r}"
    assert message == "The specified route  does not exist", message


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error_of(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidCustomerGatewayID.NotFound",
            "InvalidVpnConnectionID.NotFound",
            "InvalidVpnGatewayID.NotFound",
        ):
            raise


# budget.cleanup_timeout for behavioral/ec2: one deadline shared by the check's teardowns.
_TEARDOWN_RETRY_S = 900.0
_TEARDOWN_DEADLINES: dict = {}


def _teardown_left(ec2) -> float:
    held = _TEARDOWN_DEADLINES.get(id(ec2))
    if held is None or held[0] is not ec2:
        held = _TEARDOWN_DEADLINES[id(ec2)] = (ec2, time.monotonic() + _TEARDOWN_RETRY_S)
    return held[1] - time.monotonic()


def _retry_in_use(ec2, fn):
    """Retry fn on IncorrectState (a dependent is still deleting) and throttling every 2 s to the
    shared cleanup deadline; raise everything else."""
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("IncorrectState", "RequestLimitExceeded") or _teardown_left(ec2) <= 0:
                raise
        time.sleep(2)


def _vgw_state(ec2, vgw_id: str):
    try:
        described = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidVpnGatewayID.NotFound":
            return "pending"
        raise
    if not described:
        return "pending"
    return described[0]["State"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
