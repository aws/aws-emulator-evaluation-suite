"""e2e-vpn-tunnel-option-out-of-range-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-vpn-tunnel-option-out-of-range-rejected"
GROUP = "e2e"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpnTunnelOptions rejects a DPDTimeoutSeconds below the documented minimum of 30 with
    InvalidParameterValue and leaves the tunnel's DPD timeout untouched; the same call with a valid
    value on the same tunnel succeeds as the positive control."""
    ec2 = ctx.client("ec2")

    name_tag = ctx.unique_name("sim2real-vpn-oor-")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65000, PublicIp="203.0.113.21", Type="ipsec.1",
        TagSpecifications=_tag_spec("customer-gateway", name_tag),
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id),
        "InvalidCustomerGatewayID.NotFound"))
    _poll_until(
        lambda: ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_id])[
            "CustomerGateways"
        ][0]["State"],
        lambda state: state == "available",
        timeout_s=120,
        description="customer gateway available",
    )

    vgw_id = _create_vpn_gateway_with_retry(
        ec2, Type="ipsec.1", TagSpecifications=_tag_spec("vpn-gateway", name_tag)
    )
    ctx.on_cleanup(lambda: _delete_vpn_gateway_with_retry(ec2, vgw_id))
    _poll_until(
        lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]["State"],
        lambda state: state == "available",
        timeout_s=120,
        description="vpn gateway available",
    )

    conn = ec2.create_vpn_connection(
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        Type="ipsec.1",
        Options={"StaticRoutesOnly": True},
        TagSpecifications=_tag_spec("vpn-connection", name_tag),
    )["VpnConnection"]
    conn_id = conn["VpnConnectionId"]

    def _cleanup_vpn_connection():
        _unless_gone(lambda: ec2.delete_vpn_connection(VpnConnectionId=conn_id),
                     "InvalidVpnConnectionID.NotFound")
        # Deleting a VPN connection is asynchronous; the VGW delete above races
        # a connection still "deleting" and transiently rejects with
        # DependencyViolation (handled by the retry helper), so wait for the
        # connection to actually reach "deleted" first rather than relying on
        # that retry window alone.
        _poll_until(
            lambda: _describe_vpn(ec2, conn_id),
            lambda c: c is None or c.get("State") == "deleted",
            timeout_s=600,
            interval_s=2.0,
            description="vpn connection deleted",
        )

    ctx.on_cleanup(_cleanup_vpn_connection)

    def _tunnel_option_for(c, ip):
        opts = c.get("Options", {}).get("TunnelOptions", [])
        return next((o for o in opts if o.get("OutsideIpAddress") == ip), None)

    # VgwTelemetry appears as soon as the connection is "available"; the structured
    # Options.TunnelOptions entry for that same outside IP can lag it by minutes and
    # its individual fields (DpdTimeoutSeconds included) can lag further. Pin
    # `tunnel_ip` off VgwTelemetry alone rather than blocking the whole check on a
    # structured-field read that a fresh, never-yet-modified tunnel may not populate
    # in bounded time; the two calls below establish the DPD contract without ever
    # needing to read it beforehand.
    conn = _poll_until(
        lambda: ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0],
        lambda c: c["State"] == "available" and bool(c.get("VgwTelemetry")),
        timeout_s=900,
        interval_s=15.0,
        description="vpn connection available with telemetry",
    )
    tunnel_ip = conn["VgwTelemetry"][0]["OutsideIpAddress"]

    def _tunnel_option():
        c = ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0]
        return _tunnel_option_for(c, tunnel_ip)

    # --- The out-of-range value (below the documented minimum of 30) is rejected. ---
    code, message = _error_retry(
        lambda: ec2.modify_vpn_tunnel_options(
            VpnConnectionId=conn_id,
            VpnTunnelOutsideIpAddress=tunnel_ip,
            TunnelOptions={"DPDTimeoutSeconds": 10},
            SkipTunnelReplacement=True,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for DPDTimeoutSeconds=10 (below the documented minimum of 30), got {code!r}"
    assert message == "Invalid value specified for DPDTimeoutSeconds.", f"unexpected InvalidParameterValue message for DPDTimeoutSeconds=10: {message!r}"

    # --- Effect absent: whatever the rejected call's target reports for this
    # tunnel's DPD timeout right now, it is not the rejected value. A brand-new,
    # never-yet-modified tunnel may not report the field at all yet (see above);
    # that is itself consistent with "the rejected value was never applied".
    rejected_read = _tunnel_option()
    rejected_dpd = rejected_read.get("DpdTimeoutSeconds") if rejected_read else None
    assert rejected_dpd != 10, f"expected the rejected DPDTimeoutSeconds=10 to never appear on the tunnel, got {rejected_dpd!r}"

    # --- Positive control: a valid value on the very same tunnel succeeds. ---
    # A DPD change refuses SkipTunnelReplacement=True, so the valid modify replaces the tunnel.
    _retry_transient(
        lambda: ec2.modify_vpn_tunnel_options(
            VpnConnectionId=conn_id,
            VpnTunnelOutsideIpAddress=tunnel_ip,
            TunnelOptions={"DPDTimeoutSeconds": 45},
        )
    )
    updated = _poll_until(
        _tunnel_option,
        lambda o: o is not None and o.get("DpdTimeoutSeconds") == 45,
        timeout_s=1200,
        interval_s=15.0,
        description="tunnel DPD timeout updated to 45 after the valid modify",
    )
    assert updated["DpdTimeoutSeconds"] == 45, f"expected the valid modify to raise DpdTimeoutSeconds to 45, got {updated['DpdTimeoutSeconds']!r}"


# ===== helpers (self-contained) =====
def _tag_spec(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _unless_gone(fn, *codes) -> None:
    """Only the resource's own not-found *codes* count as already done; any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in codes:
            raise


def _error_retry(fn, timeout_s=120.0, interval_s=10.0):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that ACCEPTS input real AWS rejects is the strongest
    signal available and must not pass as a mere code mismatch. Retries
    through the transient window where a VPN connection that just reported
    "available" still rejects tunnel-level Modify* calls."""
    from botocore.exceptions import ClientError

    try:
        result = _retry_transient(fn, timeout_s=timeout_s, interval_s=interval_s)
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_transient(fn, timeout_s=120.0, interval_s=10.0):
    # Right after DescribeVpnConnections first reports State == "available",
    # real AWS can still reject tunnel-level Modify* calls for a further
    # settling window with an "UnsupportedOperation ... not in the available
    # state" error. Retry through that transient window instead of treating
    # it as a real rejection.
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


def _create_vpn_gateway_with_retry(ec2, timeout_s=600.0, interval_s=20.0, **kwargs):
    # The account's virtual private gateway limit (default quota: 5 per
    # region) is shared across every check in this suite, so it can be
    # transiently exhausted by sibling checks that haven't finished tearing
    # down their own gateways yet. Retry through it rather than failing fast
    # on a shared-quota collision that has nothing to do with this check's
    # own contract.
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
    # A virtual private gateway whose VPN connection was JUST deleted can
    # still transiently reject DeleteVpnGateway with DependencyViolation for
    # a short settling window. Retry through it instead of silently leaking
    # the gateway (the runner swallows cleanup exceptions), which would
    # otherwise permanently eat into the account's shared quota.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("DependencyViolation", "IncorrectState") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _describe_vpn(ec2, conn_id):
    items = ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"]
    return items[0] if items else None


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
