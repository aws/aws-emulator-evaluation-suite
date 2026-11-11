"""op-contract-deleteVpnConcentrator."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpnConcentrator"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpnConcentrator removes the concentrator; a bogus concentrator id is rejected."""
    ec2 = ctx.client("ec2")

    tgw_id = _create_tgw(ctx, ec2)

    created = ec2.create_vpn_concentrator(
        Type="ipsec.1",
        TransitGatewayId=tgw_id,
        TagSpecifications=[_tag_spec(ctx, "vpn-concentrator", "vcn")],
    )
    concentrator_id = created["VpnConcentrator"]["VpnConcentratorId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            _safe(lambda: ec2.delete_vpn_concentrator(VpnConcentratorId=concentrator_id))

    ctx.on_cleanup(_cleanup)

    # success path: the concentrator exists and reaches a stable (non pending) state.
    # Measured on real AWS: attaching a VPN concentrator to a transit gateway routinely
    # takes several minutes, well past a VPC/TGW attachment's usual ~1-3 minutes.
    concentrator = _poll_until(
        lambda: _items(
            ec2.describe_vpn_concentrators(VpnConcentratorIds=[concentrator_id]),
            "VpnConcentrators",
            "VpnConcentratorSet",
        )[0],
        lambda c: c["State"] != "pending",
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert concentrator["VpnConcentratorId"] == concentrator_id
    assert concentrator["Type"] == "ipsec.1"

    ec2.delete_vpn_concentrator(VpnConcentratorId=concentrator_id)
    state["deleted"] = True

    def _probe_gone():
        described = _items(
            ec2.describe_vpn_concentrators(VpnConcentratorIds=[concentrator_id]),
            "VpnConcentrators",
            "VpnConcentratorSet",
        )
        return described[0]["State"] if described else "gone"

    _poll_until(_probe_gone, lambda s: s in ("deleted", "gone"), timeout_s=120.0, interval_s=5.0)

    # distinct error boundary: a syntactically valid but nonexistent concentrator id is rejected
    bogus_id = _mutate_id(concentrator_id)
    code, msg = _client_error(lambda: ec2.delete_vpn_concentrator(VpnConcentratorId=bogus_id))
    expected_code = "InvalidVpnConcentratorID.NotFound"
    assert code == expected_code, f"expected {expected_code!r} deleting a nonexistent VPN concentrator, got {code!r}"
    expected_msg = f"The vpn-concentrator ID '{bogus_id}' does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _create_tgw(ctx, ec2):
    """CreateVpnConcentrator requires a TransitGatewayId in practice, despite the shape not
    flagging it "required" (confirmed against real AWS: MissingParameter, "must contain the
    parameter transitGatewayId"). Provision one as this check's own prerequisite."""
    name = ctx.unique_name("sim2real-behav-vcn-tgw-")
    created = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=120.0,
        interval_s=3.0,
    )
    return tgw_id


def _items(resp: dict, *keys: str) -> list:
    for key in keys:
        if key in resp:
            return resp[key]
    return []


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidTransitGatewayID.NotFound",
            "InvalidVpnConcentratorID.NotFound",
        ):
            raise


def _mutate_id(real_id: str) -> str:
    return real_id[:-1] + ("0" if real_id[-1] != "0" else "1")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
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
