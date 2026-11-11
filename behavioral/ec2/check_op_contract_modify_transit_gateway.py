"""op-contract-modify-transit-gateway."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-transit-gateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTransitGateway sets a new description, echoed and read back; an unknown gateway id fails
    with InvalidTransitGatewayID.NotFound."""
    ec2 = ctx.client("ec2")

    desc = ctx.unique_name("sim2real-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=desc,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": desc}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))

    def _describe():
        return ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]

    _poll_until(_describe, lambda t: t["State"] == "available", timeout_s=240)

    new_desc = desc + "-modified"
    resp = ec2.modify_transit_gateway(TransitGatewayId=tgw_id, Description=new_desc)
    assert resp["TransitGateway"]["Description"] == new_desc, resp["TransitGateway"]

    persisted = _describe()
    assert persisted["Description"] == new_desc, "modification did not persist"

    code = _error_code(
        lambda: ec2.modify_transit_gateway(TransitGatewayId="tgw-00000000000000000", Description="x")
    )
    assert code == "InvalidTransitGatewayID.NotFound", f"unexpected error code: {code}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
