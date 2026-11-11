"""op-contract-describe-vpn-connections."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-vpn-connections"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpnConnections: success returns the created VPN connection with the correct
    Type/CustomerGatewayId/VpnGatewayId once it settles; a bogus VpnConnectionId is rejected
    with the specific InvalidVpnConnectionID.NotFound error."""
    ec2 = ctx.client("ec2")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65000,
        PublicIp="203.0.113.12",
        Type="ipsec.1",
        TagSpecifications=_tag_spec(ctx, "customer-gateway", ctx.unique_name("sim2real-cgw-")),
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: _retry_in_use(ec2, lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id)))

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=_tag_spec(ctx, "vpn-gateway", ctx.unique_name("sim2real-vgw-")),
    )["VpnGateway"]["VpnGatewayId"]
    # DeleteVpnGateway answers IncorrectState while the VPN connection is still deleting.
    ctx.on_cleanup(lambda: _retry_in_use(ec2, lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)))

    _poll_until(
        lambda: _vgw_state(ec2, vgw_id),
        lambda s: s == "available",
        timeout_s=60.0,
    )

    conn = _create_vpn_connection_with_retry(
        ec2,
        cgw_id,
        vgw_id,
        _tag_spec(ctx, "vpn-connection", ctx.unique_name("sim2real-vpn-")),
    )
    conn_id = conn["VpnConnectionId"]
    ctx.on_cleanup(lambda: ec2.delete_vpn_connection(VpnConnectionId=conn_id))

    described = _poll_until(
        lambda: ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0],
        lambda c: c["State"] in ("available", "pending"),
        timeout_s=60.0,
    )
    assert described["Type"] == "ipsec.1", f"expected Type ipsec.1, got {described.get('Type')!r}"
    assert described["CustomerGatewayId"] == cgw_id, (
        f"expected CustomerGatewayId {cgw_id!r}, got {described.get('CustomerGatewayId')!r}"
    )
    assert described["VpnGatewayId"] == vgw_id, (
        f"expected VpnGatewayId {vgw_id!r}, got {described.get('VpnGatewayId')!r}"
    )

    error = _client_error(
        lambda: ec2.describe_vpn_connections(VpnConnectionIds=["vpn-00000000000000000"])
    )
    code = error.get("Code")
    assert code == "InvalidVpnConnectionID.NotFound", (
        f"expected InvalidVpnConnectionID.NotFound for a bogus VpnConnectionId, got {code!r} ({error!r})"
    )
    message = error.get("Message")
    expected_message = "The vpnConnection ID 'vpn-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


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


def _vgw_state(ec2, vgw_id):
    try:
        return ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]["State"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidVpnGatewayID.NotFound":
            # newly-created gateway not yet visible to all backends; keep polling
            return None
        raise


def _create_vpn_connection_with_retry(ec2, cgw_id, vgw_id, tag_specs, timeout_s=60.0, interval_s=2.0):
    """create_vpn_connection can still race a freshly-created VpnGateway that describe
    already reports as 'available'; retry on the specific NotFound until it settles."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpn_connection(
                CustomerGatewayId=cgw_id,
                VpnGatewayId=vgw_id,
                Type="ipsec.1",
                TagSpecifications=tag_specs,
            )["VpnConnection"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpnGatewayID.NotFound" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a bogus id real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects DescribeVpnConnections for a bogus VpnConnectionId, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

