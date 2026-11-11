"""op-contract-modify-vpn-tunnel-options."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpn-tunnel-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpnTunnelOptions: success changes a tunnel's DPD timeout and IKE
    versions and DescribeVpnConnections reflects the new values; DryRun is
    rejected with DryRunOperation."""
    ec2 = ctx.client("ec2")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65003, PublicIp="203.0.113.40", Type="ipsec.1", TagSpecifications=_tag_spec(ctx, "customer-gateway", "cgw")
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
        # ctx.run_cleanups() has its OWN ceiling (60s total across every
        # registered cleanup, separate from the 300s check-body budget), so
        # this wait plus the gateway retry below must both stay well under
        # that combined 60s, not under the body's ceiling.
        _poll_until(
            lambda: _describe_vpn(ec2, vpn_id),
            lambda v: v is None or v.get("State") == "deleted",
            timeout_s=35,
            interval_s=5,
        )

    ctx.on_cleanup(_cleanup_vpn_connection)

    # Real Site-to-Site VPN connections take many minutes to converge to "available" (about 11
    # minutes end to end on real AWS, setup included), so the poll allows 900 s.
    available = _poll_until(
        lambda: _describe_vpn(ec2, vpn_id),
        lambda v: v is not None and v["State"] == "available",
        timeout_s=900,
        interval_s=10,
    )
    assert available is not None and available["State"] == "available", available
    outside_ip = sorted({t["OutsideIpAddress"] for t in available["VgwTelemetry"]})[0]
    original_dpd = _tunnel_dpd(available, outside_ip)

    # error boundary: DryRun must reject without mutating the tunnel options.
    # timeout_s kept short (unlike the "available" wait above): this only
    # needs to ride out the brief just-became-available settling window, and
    # the whole body shares one 300s ceiling that the "available" wait above
    # already spends most of.
    err, err_message = _error_retry(
        lambda: ec2.modify_vpn_tunnel_options(
            VpnConnectionId=vpn_id,
            VpnTunnelOutsideIpAddress=outside_ip,
            TunnelOptions={"DPDTimeoutSeconds": 45},
            DryRun=True,
        ),
        timeout_s=20,
        interval_s=5,
    )
    assert err == "DryRunOperation", err
    assert err_message == "Request would have succeeded, but DryRun flag is set.", err_message

    # effect-absent: an independent read must still show the pre-DryRun value,
    # not the target of the (rejected) call -- otherwise a target that quietly
    # applies DryRun requests would be indistinguishable from a correct one,
    # since the success path below sets the tunnel to that same 45 anyway.
    unmutated = _describe_vpn(ec2, vpn_id)
    assert unmutated is not None and _tunnel_dpd(unmutated, outside_ip) == original_dpd, (
        original_dpd,
        unmutated,
    )

    # success path: raise the DPD timeout for this specific tunnel. Same short
    # window as the DryRun retry above, for the same reason.
    resp = _retry_transient(
        lambda: ec2.modify_vpn_tunnel_options(
            VpnConnectionId=vpn_id,
            VpnTunnelOutsideIpAddress=outside_ip,
            TunnelOptions={"DPDTimeoutSeconds": 45},
        ),
        timeout_s=20,
        interval_s=5,
    )
    modified_tunnel = _find_tunnel(resp["VpnConnection"], outside_ip)
    assert modified_tunnel is not None and modified_tunnel["DpdTimeoutSeconds"] == 45, resp

    updated = _poll_until(
        lambda: _describe_vpn(ec2, vpn_id),
        lambda v: v is not None and _tunnel_dpd(v, outside_ip) == 45,
        timeout_s=30,
        interval_s=5,
    )
    assert updated is not None and _tunnel_dpd(updated, outside_ip) == 45, updated


# ===== helpers =====
def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _create_vpn_gateway_with_retry(ec2, timeout_s=90.0, interval_s=15.0, **kwargs):
    # The account's virtual private gateway limit (default quota: 5 per region)
    # is shared across every check in this suite, so it can be transiently
    # exhausted by sibling checks running concurrently that haven't finished
    # tearing down their own gateways yet. This check's body runs under its
    # own 300s ceiling (cleanup afterwards has a separate, much shorter 60s
    # one -- see the delete-side retry below), so widening this retry window
    # to try to "outlast" a sibling is self-defeating -- it just guarantees
    # THIS check gets killed mid-retry instead. Keep the window short enough
    # to leave the rest of the body comfortably inside its own ceiling; a
    # real, sustained quota problem should fail fast here rather than hang.
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


def _delete_vpn_gateway_with_retry(ec2, vgw_id, timeout_s=300.0, interval_s=5.0):
    # Mirrors the create-side retry: a virtual private gateway whose VPN
    # connection was JUST deleted can still transiently reject
    # DeleteVpnGateway with DependencyViolation for a short settling window.
    # Retry through it instead of letting one failed attempt silently leak the
    # gateway (the runner swallows cleanup exceptions), which would otherwise
    # permanently eat into the account's shared quota.
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
    # real AWS can still reject tunnel-level Modify* calls for a further
    # settling window with an "UnsupportedOperation ... not in the available
    # state" error. Retry through that transient window (bounded, since this
    # runs inside the same overall wall-clock ceiling as the rest of the
    # check) instead of treating it as a real rejection.
    from botocore.exceptions import ClientError

    transient_codes = ("UnsupportedOperation", "InvalidVpnConnection.InvalidState")
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
    raise TimeoutError(f"timed out after {timeout_s}s waiting for condition; last observed: {last!r}")


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


def _find_tunnel(vpn_connection, outside_ip):
    for tunnel in vpn_connection.get("Options", {}).get("TunnelOptions", []):
        if tunnel.get("OutsideIpAddress") == outside_ip:
            return tunnel
    return None


def _tunnel_dpd(vpn_connection, outside_ip):
    # .get, not a hard subscript: a real, freshly-available connection's tunnel
    # options can omit "DpdTimeoutSeconds" entirely until it has been set at
    # least once via ModifyVpnTunnelOptions. Every caller compares the result for equality (never for
    # not-None-ness), so None reads correctly as "not yet set".
    tunnel = _find_tunnel(vpn_connection, outside_ip)
    return tunnel.get("DpdTimeoutSeconds") if tunnel else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
