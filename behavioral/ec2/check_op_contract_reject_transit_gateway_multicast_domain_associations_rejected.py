"""op-contract-reject-transit-gateway-multicast-domain-associations-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-reject-transit-gateway-multicast-domain-associations-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectTransitGatewayMulticastDomainAssociations with DryRun fails with DryRunOperation and the
    standard message; an unknown multicast domain id fails with its NotFound code and exact message;
    both answers carry a RequestId."""
    ec2 = ctx.client("ec2")
    fake_domain_id = "tgw-mcast-domain-00000000000000000"

    # --- boundary A: DryRun short-circuits regardless of resource existence ---
    info = _client_error_info(
        lambda: ec2.reject_transit_gateway_multicast_domain_associations(
            DryRun=True, TransitGatewayMulticastDomainId=fake_domain_id
        )
    )
    assert (info["code"], info["message"]) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {info!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    # --- boundary B: unknown multicast domain id is a distinct NotFound error ---
    info = _client_error_info(
        lambda: ec2.reject_transit_gateway_multicast_domain_associations(
            TransitGatewayMulticastDomainId=fake_domain_id
        )
    )
    expected = (
        "InvalidTransitGatewayMulticastDomainId.NotFound",
        f"The transit-gateway-multicast-domain ID '{fake_domain_id}' does not exist",
    )
    assert (info["code"], info["message"]) == expected, f"expected {expected!r}, got {info!r}"
    assert info["request_id"], "expected a RequestId in ResponseMetadata"


def _client_error_info(fn):
    """Call fn(); return its botocore Error dict plus RequestId. An unexpected SUCCESS raises,
    because real AWS refusing this call is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {
            "code": err["Code"],
            "message": err.get("Message"),
            "request_id": exc.response.get("ResponseMetadata", {}).get("RequestId"),
        }
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
