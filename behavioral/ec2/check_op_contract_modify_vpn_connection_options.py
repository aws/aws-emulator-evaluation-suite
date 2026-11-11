"""op-contract-modify-vpn-connection-options."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpn-connection-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpnConnectionOptions: success narrows the on-premises (local) IPv4
    CIDR advertised over the tunnel and DescribeVpnConnections reflects the new
    Options.LocalIpv4NetworkCidr; DryRun is rejected with DryRunOperation."""
    ec2 = ctx.client("ec2")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65001, PublicIp="203.0.113.20", Type="ipsec.1", TagSpecifications=_tag_spec(ctx, "customer-gateway", "cgw")
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))

    vgw_id = _create_vpn_gateway_with_retry(ec2, Type="ipsec.1", TagSpecifications=_tag_spec(ctx, "vpn-gateway", "vgw"))
    ctx.on_cleanup(lambda: _delete_vpn_gateway_with_retry(ec2, vgw_id))

    # A freshly created virtual private gateway is not immediately visible to
    # CreateVpnConnection on real AWS (eventual consistency) — wait for it to
    # report "available" before referencing it.
    _wait_for_vgw_available(ec2, vgw_id)

    vpn_id = ec2.create_vpn_connection(
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        Type="ipsec.1",
        Options={"StaticRoutesOnly": True},
        TagSpecifications=_tag_spec(ctx, "vpn-connection", "vpn"),
    )["VpnConnection"]["VpnConnectionId"]

    def _cleanup_vpn_connection():
        ec2.delete_vpn_connection(VpnConnectionId=vpn_id)
        # Deleting a VPN connection is asynchronous — the connection lingers in
        # "deleting" for a while, and a virtual private gateway that still has
        # it attached will transiently reject DeleteVpnGateway with
        # DependencyViolation. Wait for the connection to actually reach
        # "deleted" before returning, so the gateway cleanup below doesn't race
        # it (a race that would otherwise silently leak the gateway — the
        # runner swallows cleanup exceptions — and permanently eat into the
        # account's shared virtual-private-gateway quota).
        # Cleanup itself runs inside the same overall per-check wall-clock
        # budget as the test body, so this must stay bounded well under that
        # ceiling rather than being generously widened (see the create-side
        # retry helper below for the full rationale).
        _poll_until(
            lambda: _describe_vpn(ec2, vpn_id),
            lambda v: v is None or v.get("State") == "deleted",
            timeout_s=90,
            interval_s=10,
        )

    ctx.on_cleanup(_cleanup_vpn_connection)

    # Real Site-to-Site VPN connections routinely take a couple of minutes to
    # converge to "available" -- budget more than a token amount here.
    available = _poll_until(
        lambda: _describe_vpn(ec2, vpn_id),
        lambda v: v is not None and v["State"] == "available",
        timeout_s=150,
        interval_s=5,
    )
    assert available is not None and available["Options"]["LocalIpv4NetworkCidr"] == "0.0.0.0/0", available

    # error boundary: DryRun must reject without mutating the connection options.
    # Right after DescribeVpnConnections first reports State == "available",
    # real AWS can still transiently reject Modify* calls with
    # InvalidVpnConnection.InvalidState while it finishes settling the
    # connection. Retry through that transient window (bounded, since this
    # runs inside the same overall wall-clock ceiling as the rest of the
    # check) so the boundary being tested (DryRun) is the one that decides
    # the outcome.
    err, err_message = _error_retry(
        lambda: ec2.modify_vpn_connection_options(VpnConnectionId=vpn_id, LocalIpv4NetworkCidr="10.55.0.0/16", DryRun=True)
    )
    assert err == "DryRunOperation", err
    assert err_message == "Request would have succeeded, but DryRun flag is set.", err_message
    still_default = _describe_vpn(ec2, vpn_id)
    assert still_default["Options"]["LocalIpv4NetworkCidr"] == "0.0.0.0/0", still_default

    # success path: narrow the on-premises network CIDR advertised over the tunnel.
    resp = _retry_transient(
        lambda: ec2.modify_vpn_connection_options(VpnConnectionId=vpn_id, LocalIpv4NetworkCidr="10.55.0.0/16"),
        timeout_s=600.0,
    )
    assert resp["VpnConnection"]["Options"]["LocalIpv4NetworkCidr"] == "10.55.0.0/16", resp

    updated = _poll_until(
        lambda: _describe_vpn(ec2, vpn_id),
        lambda v: v is not None and v["Options"]["LocalIpv4NetworkCidr"] == "10.55.0.0/16" and v["State"] == "available",
        timeout_s=90,
        interval_s=5,
    )
    assert updated is not None and updated["Options"]["LocalIpv4NetworkCidr"] == "10.55.0.0/16", updated


def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _create_vpn_gateway_with_retry(ec2, timeout_s=90.0, interval_s=15.0, **kwargs):
    # The account's virtual private gateway limit (default quota: 5 per region)
    # is shared across every check in this suite, so it can be transiently
    # exhausted by sibling checks running concurrently that haven't finished
    # tearing down their own gateways yet. This check runs under a hard,
    # whole-process wall-clock ceiling (including its own teardown) that is
    # considerably shorter than a sibling's full multi-minute lifecycle, so
    # widening this retry window to try to "outlast" a sibling is
    # self-defeating -- it just guarantees THIS check gets killed mid-retry
    # instead. Keep the window short enough to leave the rest of this check
    # (and its cleanup) comfortably inside the overall ceiling; a real,
    # sustained quota problem should fail fast here rather than hang.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpn_gateway(**kwargs)["VpnGateway"]["VpnGatewayId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "VpnGatewayLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_vpn_gateway_with_retry(ec2, vgw_id, timeout_s=300.0, interval_s=10.0):
    # Mirrors the create-side retry: a virtual private gateway whose VPN
    # connection was JUST deleted can still transiently reject
    # DeleteVpnGateway with DependencyViolation for a short settling window.
    # Retry through it instead of letting one failed attempt silently leak the
    # gateway (the runner swallows cleanup exceptions), which would otherwise
    # permanently eat into the account's shared quota -- but keep the window
    # short, since cleanup runs inside the same overall wall-clock ceiling as
    # the rest of the check.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            # IncorrectState ("The VPN gateway is in use") holds until the VPN
            # connection that used the gateway finishes deleting.
            if code in ("DependencyViolation", "IncorrectState") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _retry_transient(fn, timeout_s=120.0, interval_s=10.0):
    # Right after DescribeVpnConnections first reports State == "available",
    # real AWS can still reject Modify* calls for a short window with a
    # transient "not in the available state" error while it finishes
    # settling the connection. Retry through that transient window instead of
    # treating it as a real rejection -- bounded, since this runs inside the
    # same overall wall-clock ceiling as the rest of the check.
    from botocore.exceptions import ClientError

    transient_codes = ("InvalidVpnConnection.InvalidState", "UnsupportedOperation")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in transient_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _error_retry(fn, timeout_s=120.0, interval_s=10.0):
    """Return the (code, message) of the error fn() raises once the settling window
    passes. A call that SUCCEEDS raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = _retry_transient(fn, timeout_s=timeout_s, interval_s=interval_s)
    except ClientError as exc:
        err = exc.response.get("Error", {})
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
    return last


def _describe_vpn(ec2, vpn_id):
    resp = ec2.describe_vpn_connections(VpnConnectionIds=[vpn_id])
    items = resp.get("VpnConnections", [])
    return items[0] if items else None


def _wait_for_vgw_available(ec2, vgw_id, timeout_s=60.0, interval_s=5.0):
    def _describe():
        resp = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])
        items = resp.get("VpnGateways", [])
        return items[0] if items else None

    return _poll_until(_describe, lambda v: v is not None and v.get("State") == "available", timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
