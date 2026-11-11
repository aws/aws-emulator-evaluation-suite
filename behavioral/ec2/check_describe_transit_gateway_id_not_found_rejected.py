"""describe-transit-gateway-id-not-found-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-transit-gateway-id-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTransitGateways rejects an unknown id with InvalidTransitGatewayID.NotFound and a
    wrong-prefix id with InvalidTransitGatewayID.Malformed, each with its exact message; a created
    gateway describes back first.
    """
    ec2 = ctx.client("ec2")

    real_id = _create_tgw(ctx, ec2)
    described = ec2.describe_transit_gateways(TransitGatewayIds=[real_id])["TransitGateways"]
    assert described and described[0]["TransitGatewayId"] == real_id, (
        f"positive control failed: describe of the just-created {real_id} "
        f"did not reflect it, got {described!r}"
    )

    # a syntactically valid but never-allocated transit-gateway id
    bogus_id = "tgw-00000000000000000"

    code, message = _error_code(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[bogus_id])
    )
    assert code == "InvalidTransitGatewayID.NotFound", (
        f"expected InvalidTransitGatewayID.NotFound, got {code!r}"
    )
    expected = f"Transit Gateway {bogus_id} was deleted or does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # a malformed id (wrong resource-type prefix) must be rejected with a distinct,
    # syntax-level error rather than the existence-lookup NotFound above
    malformed_id = "vpc-00000000000000000"
    code_malformed, message_malformed = _error_code(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[malformed_id])
    )
    assert code_malformed == "InvalidTransitGatewayID.Malformed", (
        f"expected InvalidTransitGatewayID.Malformed for mismatched-prefix id, got {code_malformed!r}"
    )
    expected = f"Invalid Transit Gateway id {malformed_id}."
    assert message_malformed == expected, (
        f"expected message {expected!r}, got {message_malformed!r}"
    )
    assert code_malformed != code, "malformed-id boundary must differ from NotFound boundary"


# Codes that mean this account/region cannot create a transit gateway right now
# (quota exhausted, service not enabled, or not authorized) -- a prerequisite
# gap that still fails the check, since a check never skips.
_TGW_UNAVAILABLE = {
    "TransitGatewayLimitExceeded",
    "MaxTransitGatewayLimitExceeded",
    "OptInRequired",
    "UnauthorizedOperation",
    "AccessDenied",
    "UnsupportedOperation",
    "InvalidAction",
}


def _create_tgw(ctx, ec2) -> str:
    try:
        tgw = ec2.create_transit_gateway(
            Description="sim2real behavioral positive control",
            TagSpecifications=[
                {"ResourceType": "transit-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}
            ],
        )["TransitGateway"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _TGW_UNAVAILABLE or "LimitExceeded" in code:
            raise AssertionError(f"transit gateway not creatable on this account ({code})") from exc
        raise
    tgw_id = tgw["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    return tgw_id


def _delete_tgw(ec2, tgw_id: str) -> None:
    """A TGW rejects deletion while 'pending', so poll to a deletable state first."""
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            tgws = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
                raise
            return
        if not tgws or tgws[0]["State"] in ("deleting", "deleted"):
            return
        if tgws[0]["State"] == "available":
            break
        time.sleep(5)
    try:
        ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise


def _error_code(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
