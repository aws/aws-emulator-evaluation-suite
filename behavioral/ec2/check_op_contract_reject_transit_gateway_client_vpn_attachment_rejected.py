"""op-contract-reject-transit-gateway-client-vpn-attachment-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-reject-transit-gateway-client-vpn-attachment-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectTransitGatewayClientVpnAttachment with DryRun fails with DryRunOperation and the standard
    message; an unknown attachment id fails with InvalidTransitGatewayAttachmentID.NotFound and its
    exact message; both answers carry a RequestId."""
    ec2 = ctx.client("ec2")
    fake_attachment_id = "tgw-attach-00000000000000000"

    # --- boundary A: DryRun short-circuits regardless of resource existence ---
    info = _client_error_info(
        lambda: ec2.reject_transit_gateway_client_vpn_attachment(
            DryRun=True, TransitGatewayAttachmentId=fake_attachment_id
        )
    )
    assert (info["code"], info["message"]) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {info!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    # --- boundary B: unknown attachment id is a distinct NotFound error ---
    info = _client_error_info(
        lambda: ec2.reject_transit_gateway_client_vpn_attachment(
            TransitGatewayAttachmentId=fake_attachment_id
        )
    )
    expected = (
        "InvalidTransitGatewayAttachmentID.NotFound",
        f"The transit-gateway-attachment ID '{fake_attachment_id}' does not exist",
    )
    assert (info["code"], info["message"]) == expected, f"expected {expected!r}, got {info!r}"
    assert info["request_id"], "expected a RequestId in ResponseMetadata"


def _client_error_info(fn):
    """Call fn(); return its botocore Error code and message plus RequestId. A success raises:
    an accepted call is the strongest signal and must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {
            "code": err["Code"],
            "message": err.get("Message"),
            "request_id": exc.response.get("ResponseMetadata", {}).get("RequestId"),
        }
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
