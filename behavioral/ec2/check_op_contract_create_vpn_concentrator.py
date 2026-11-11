"""op-contract-createVpnConcentrator."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createVpnConcentrator"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpnConcentrator creates a concentrator attached to the required transit gateway, confirmed
    by an independent DescribeVpnConcentrators read, and DryRun short-circuits before creation."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "create_vpn_concentrator"):
        raise AssertionError("installed botocore lacks create_vpn_concentrator")

    tgw_id = ec2.create_transit_gateway(
        Description=ctx.unique_name("sim2real-vcn-tgw-"),
        TagSpecifications=[_tag_spec(ctx, "transit-gateway", "vcn-tgw")],
    )["TransitGateway"]["TransitGatewayId"]

    def _cleanup_tgw() -> None:
        # The concentrator's transit-gateway attachment leaves asynchronously; DeleteTransitGateway
        # refuses with IncorrectState until it has gone, so wait for it inside the teardown window.
        def _attachments_drained():
            atts = ec2.describe_transit_gateway_attachments(
                Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
            )["TransitGatewayAttachments"]
            return all(a.get("State") == "deleted" for a in atts)

        _poll_until(
            _attachments_drained, bool, timeout_s=_teardown_left(), interval_s=15.0,
            description="transit gateway attachments draining",
        )
        _retry_delete(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id), timeout_s=_teardown_left())

    ctx.on_cleanup(_cleanup_tgw)

    # A just-created transit gateway is not always immediately resolvable by dependent create
    # calls (eventual consistency) -- poll until it reaches "available" before referencing it,
    # instead of racing it and getting a spurious InvalidTransitGatewayID.NotFound.
    def _tgw_state():
        tgws = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"]
        return tgws[0]["State"] if tgws else "unknown"

    tgw_state = _poll_until(
        _tgw_state, lambda s: s == "available", timeout_s=600, interval_s=10,
        description="transit gateway reaching 'available'",
    )
    assert tgw_state == "available", f"transit gateway never reached 'available' (state={tgw_state!r})"

    # Error boundary: DryRun must short-circuit before creating anything. An unexpected SUCCESS
    # is the strongest possible signal (the target ignored DryRun and created a real resource),
    # so it must raise rather than be reported as a code mismatch -- and the leaked resource still
    # gets torn down.
    leaked_id: dict[str, str] = {}

    def _register_leak(result: dict) -> None:
        vc = (result or {}).get("VpnConcentrator") or {}
        vc_id = vc.get("VpnConcentratorId")
        if vc_id:
            leaked_id["id"] = vc_id
            ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpn_concentrator(VpnConcentratorId=vc_id)))

    err = _client_error(
        lambda: ec2.create_vpn_concentrator(Type="ipsec.1", TransitGatewayId=tgw_id, DryRun=True),
        on_unexpected_success=_register_leak,
    )
    assert err.get("Code") == "DryRunOperation", f"expected DryRunOperation, got {err!r} (leaked={leaked_id!r})"
    assert err.get("Message") == _DRY_RUN_MESSAGE, f"unexpected DryRun message: {err!r}"

    resp = ec2.create_vpn_concentrator(
        Type="ipsec.1",
        TransitGatewayId=tgw_id,
        TagSpecifications=[_tag_spec(ctx, "vpn-concentrator", "vcn")],
    )
    concentrator = resp["VpnConcentrator"]
    concentrator_id = concentrator["VpnConcentratorId"]

    released = {"done": False}

    def _cleanup() -> None:
        if released["done"]:
            return
        # Reached only when run() stopped before releasing it; a concentrator still settling
        # refuses deletion, so retry inside the teardown window.
        _retry_delete(
            lambda: ec2.delete_vpn_concentrator(VpnConcentratorId=concentrator_id), timeout_s=_teardown_left()
        )

    ctx.on_cleanup(_cleanup)

    assert concentrator["Type"] == "ipsec.1", f"expected Type 'ipsec.1', got {concentrator['Type']!r}"
    assert concentrator["State"] in ("pending", "available"), (
        f"unexpected initial State {concentrator['State']!r}"
    )
    assert concentrator_id.startswith("vcn-"), f"expected a 'vcn-' prefixed id, got {concentrator_id!r}"

    # Terminal read: independent of the mutating CreateVpnConcentrator response, through
    # DescribeVpnConcentrators. This is what actually proves the transit-gateway attachment the
    # docstring claims, rather than trusting the create call's own echo.
    def _described():
        items = ec2.describe_vpn_concentrators(VpnConcentratorIds=[concentrator_id])["VpnConcentrators"]
        return items[0] if items else None

    seen = _poll_until(
        _described, lambda c: c is not None and c["State"] != "pending", timeout_s=600, interval_s=10,
        description="independent read of the created concentrator settling out of 'pending'",
    )
    assert seen is not None, f"DescribeVpnConcentrators returned nothing for {concentrator_id!r}"
    assert seen["VpnConcentratorId"] == concentrator_id, seen
    assert seen["Type"] == "ipsec.1", f"independent read expected Type 'ipsec.1', got {seen['Type']!r}"
    assert seen["TransitGatewayId"] == tgw_id, (
        f"expected the concentrator attached to {tgw_id!r}; independent read shows "
        f"{seen.get('TransitGatewayId')!r}"
    )

    # Release the concentrator inside the run budget: its transit-gateway attachment drains for
    # several minutes, which the teardown window alone does not cover. Ungraded.
    _retry_delete(lambda: ec2.delete_vpn_concentrator(VpnConcentratorId=concentrator_id), timeout_s=300.0)
    released["done"] = True


# ===== helpers =====
def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _client_error(fn, on_unexpected_success=None):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    if on_unexpected_success is not None:
        on_unexpected_success(result)
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpnConcentratorID.NotFound":
            raise


# One teardown window shared by every cleanup of this check, inside the suite's cleanup budget.
_TEARDOWN_S = 840.0
_TEARDOWN_DEADLINE: list = []


def _teardown_left() -> float:
    import time

    if not _TEARDOWN_DEADLINE:
        _TEARDOWN_DEADLINE.append(time.monotonic() + _TEARDOWN_S)
    return max(_TEARDOWN_DEADLINE[0] - time.monotonic(), 1.0)


def _retry_delete(fn, timeout_s: float, interval_s: float = 15.0) -> None:
    """Teardown delete: done on success or not-found; retry IncorrectState/DependencyViolation
    until timeout_s, then re-raise so a leak is loud."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code not in ("IncorrectState", "DependencyViolation") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, description="condition"):
    import time

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
