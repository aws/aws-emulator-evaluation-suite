"""op-contract-describe-vpn-concentrators."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-vpn-concentrators"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags(
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "axis:rejection",
)
def run(ctx) -> None:
    """DescribeVpnConcentrators lists a concentrator created on a transit gateway, returns exactly it
    with that gateway's ID when filtered by its ID, and fails an unknown concentrator ID with
    InvalidVpnConcentratorId.NotFound and its exact message."""

    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "describe_vpn_concentrators"):
        raise AssertionError("describe_vpn_concentrators not supported by installed botocore")

    tgw_id = ec2.create_transit_gateway(
        Description=ctx.unique_name("sim2real-dvc-tgw-"),
        TagSpecifications=[_tag_spec(ctx, "transit-gateway", "dvc-tgw")],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))

    tgw_state = _poll_until(
        lambda: _tgw_state(ec2, tgw_id), lambda s: s == "available", timeout_s=600, interval_s=5
    )
    assert tgw_state == "available", f"transit gateway never reached 'available' (state={tgw_state!r})"

    created = ec2.create_vpn_concentrator(
        Type="ipsec.1",
        TransitGatewayId=tgw_id,
        TagSpecifications=[_tag_spec(ctx, "vpn-concentrator", "dvc-vcn")],
    )
    concentrator_id = created["VpnConcentrator"]["VpnConcentratorId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: ec2.delete_vpn_concentrator(VpnConcentratorId=concentrator_id))
    )

    # success path: an independent read -- both unfiltered and id-filtered -- sees the
    # real concentrator with the fields the contract promises.
    unfiltered = ec2.describe_vpn_concentrators()
    assert "VpnConcentrators" in unfiltered
    assert isinstance(unfiltered["VpnConcentrators"], list)
    ids_seen = {c["VpnConcentratorId"] for c in unfiltered["VpnConcentrators"]}
    assert concentrator_id in ids_seen, (
        f"created concentrator {concentrator_id} not visible in unfiltered describe: {ids_seen}"
    )

    filtered = ec2.describe_vpn_concentrators(VpnConcentratorIds=[concentrator_id])[
        "VpnConcentrators"
    ]
    assert len(filtered) == 1, f"expected exactly one match for {concentrator_id}, got {filtered}"
    concentrator = filtered[0]
    assert concentrator["VpnConcentratorId"] == concentrator_id
    assert "State" in concentrator
    assert concentrator["TransitGatewayId"] == tgw_id, concentrator.get("TransitGatewayId")

    # distinct error boundary: a syntactically valid but never-created concentrator id,
    # derived from the real one, is rejected with the specific not-found code.
    bogus_id = _mutate_id(concentrator_id)
    code, message = _error(lambda: ec2.describe_vpn_concentrators(VpnConcentratorIds=[bogus_id]))
    assert code == "InvalidVpnConcentratorId.NotFound", code
    assert message == f"The VPN concentrator '{bogus_id}' does not exist", (
        f"unexpected InvalidVpnConcentratorId.NotFound message: {message!r}"
    )


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _tgw_state(ec2, tgw_id):
    tgws = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"]
    return tgws[0]["State"] if tgws else "unknown"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _mutate_id(real_id: str) -> str:
    return real_id[:-1] + ("0" if real_id[-1] != "0" else "1")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidTransitGatewayID.NotFound",
            "InvalidVpnConcentratorID.NotFound",
        ):
            raise


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
