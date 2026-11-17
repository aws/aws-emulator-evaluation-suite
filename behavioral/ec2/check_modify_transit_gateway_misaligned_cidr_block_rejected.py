"""modify-transit-gateway-misaligned-cidr-block-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-transit-gateway-misaligned-cidr-block-rejected"
GROUP = "transit-gateway"
SERVICES = ["ec2"]


def _poll_until(probe, predicate, *, timeout_s=240.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyTransitGateway refuses a CIDR block whose address does not align to its own
    prefix length, naming the block, and the gateway's CIDR blocks are left unchanged."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(_teardown(
        lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id),
        "InvalidTransitGatewayID.NotFound",
    ))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        description=f"transit gateway {tgw_id} available",
    )

    # Positive control: a CIDR aligned to its own prefix length is accepted.
    aligned = ec2.modify_transit_gateway(
        TransitGatewayId=tgw_id,
        Options={"AddTransitGatewayCidrBlocks": ["10.100.0.0/16"]},
    )["TransitGateway"]["Options"]
    assert aligned["TransitGatewayCidrBlocks"] == ["10.100.0.0/16"], (
        f"expected the aligned CIDR to be accepted, got {aligned['TransitGatewayCidrBlocks']!r}"
    )

    # Negative: a /8 block whose base address has host bits set.
    misaligned = "10.101.0.0/8"
    code, message = _error(lambda: ec2.modify_transit_gateway(
        TransitGatewayId=tgw_id,
        Options={"AddTransitGatewayCidrBlocks": [misaligned]},
    ))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}: {message!r}"
    assert message == (
        "All Transit Gateway CIDR blocks must be a valid IPv4 or IPv6 CIDR and align with the "
        f"first address in the block.  Invalid block: {misaligned}"
    ), f"unexpected message {message!r}"

    described = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
    assert described["Options"]["TransitGatewayCidrBlocks"] == ["10.100.0.0/16"], (
        f"the refused add changed the gateway's CIDR blocks: {described['Options']['TransitGatewayCidrBlocks']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
