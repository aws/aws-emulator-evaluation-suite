"""op-contract-acceptTransitGatewayMulticastDomainAssociations."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptTransitGatewayMulticastDomainAssociations"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptTransitGatewayMulticastDomainAssociations with DryRun fails DryRunOperation, and with
    well-formed nonexistent domain and attachment ids fails
    InvalidTransitGatewayAttachmentID.NotFound, each with its exact message.
    """
    ec2 = ctx.client("ec2")
    fake_domain_id = "tgw-mcast-domain-0123456789abcdef0"
    fake_attach_id = "tgw-attach-0123456789abcdef0"

    info = _error_info(
        lambda: ec2.accept_transit_gateway_multicast_domain_associations(
            TransitGatewayMulticastDomainId=fake_domain_id,
            TransitGatewayAttachmentId=fake_attach_id,
            DryRun=True,
        )
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {info['message']!r}"
    )

    info2 = _error_info(
        lambda: ec2.accept_transit_gateway_multicast_domain_associations(
            TransitGatewayMulticastDomainId=fake_domain_id,
            TransitGatewayAttachmentId=fake_attach_id,
        )
    )
    assert info2["code"] == "InvalidTransitGatewayAttachmentID.NotFound", (
        f"expected InvalidTransitGatewayAttachmentID.NotFound, got {info2['code']!r}"
    )
    expected2 = f"The transit-gateway-attachment ID '{fake_attach_id}' does not exist"
    assert info2["message"] == expected2, (
        f"expected message {expected2!r}, got {info2['message']!r}"
    )


def _error_info(fn):
    """Call fn(); return its botocore error. An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses is not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"code": err["Code"], "message": err.get("Message")}
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
