"""op-contract-acceptTransitGatewayPeeringAttachment."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptTransitGatewayPeeringAttachment"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptTransitGatewayPeeringAttachment with DryRun fails DryRunOperation, and on a
    well-formed nonexistent attachment id fails InvalidTransitGatewayAttachmentID.NotFound, each
    with its exact message and a RequestId.
    """
    ec2 = ctx.client("ec2")
    fake_id = "tgw-attach-0123456789abcdef0"  # well-formed, guaranteed not to exist

    info = _client_error_info(
        lambda: ec2.accept_transit_gateway_peering_attachment(
            TransitGatewayAttachmentId=fake_id, DryRun=True
        )
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {info['message']!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    info2 = _client_error_info(
        lambda: ec2.accept_transit_gateway_peering_attachment(
            TransitGatewayAttachmentId=fake_id
        )
    )
    assert info2["code"] == "InvalidTransitGatewayAttachmentID.NotFound", (
        f"expected InvalidTransitGatewayAttachmentID.NotFound, got {info2['code']!r}"
    )
    expected2 = f"Transit Gateway Attachment {fake_id} was deleted or does not exist."
    assert info2["message"] == expected2, (
        f"expected message {expected2!r}, got {info2['message']!r}"
    )
    assert info2["request_id"], "expected a RequestId in ResponseMetadata"


def _client_error_info(fn):
    """Call fn(); return its botocore error. An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses is not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {
            "code": err["Code"],
            "message": err.get("Message"),
            "request_id": exc.response.get("ResponseMetadata", {}).get("RequestId"),
        }
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
