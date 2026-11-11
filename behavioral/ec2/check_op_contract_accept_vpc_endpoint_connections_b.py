"""op-contract-acceptVpcEndpointConnections-b."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptVpcEndpointConnections-b"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptVpcEndpointConnections fails InvalidVpcEndpointServiceId.NotFound for a well-formed
    unowned service id with and without DryRun, and InvalidVpcEndpointServiceId.Malformed for a
    malformed one, each with its exact message and a RequestId.
    """
    ec2 = ctx.client("ec2")
    fake_service_id = "vpce-svc-0fedcba987654321f"
    fake_endpoint_id = "vpce-0fedcba987654321f"

    info = _client_error_info(
        lambda: ec2.accept_vpc_endpoint_connections(
            ServiceId=fake_service_id, VpcEndpointIds=[fake_endpoint_id], DryRun=True
        )
    )
    assert info["code"] == "InvalidVpcEndpointServiceId.NotFound", (
        f"expected InvalidVpcEndpointServiceId.NotFound, got {info['code']!r}"
    )
    not_found_message = f"The VpcEndpointService Id '{fake_service_id}' does not exist"
    assert info["message"] == not_found_message, (
        f"expected message {not_found_message!r}, got {info['message']!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    info2 = _client_error_info(
        lambda: ec2.accept_vpc_endpoint_connections(
            ServiceId=fake_service_id, VpcEndpointIds=[fake_endpoint_id]
        )
    )
    assert info2["code"] == "InvalidVpcEndpointServiceId.NotFound", (
        f"expected InvalidVpcEndpointServiceId.NotFound, got {info2['code']!r}"
    )
    assert info2["message"] == not_found_message, (
        f"expected message {not_found_message!r}, got {info2['message']!r}"
    )
    assert info2["request_id"], "expected a RequestId in ResponseMetadata"

    info3 = _client_error_info(
        lambda: ec2.accept_vpc_endpoint_connections(
            ServiceId="__NOT_A_SERVICE_ID__", VpcEndpointIds=[fake_endpoint_id]
        )
    )
    assert info3["code"] == "InvalidVpcEndpointServiceId.Malformed", (
        "a syntactically malformed ServiceId must fail request-parameter "
        f"validation (InvalidVpcEndpointServiceId.Malformed), not the "
        f"ownership NotFound check; got {info3['code']!r}"
    )
    malformed_message = (
        "Invalid Id: '__NOT_A_SERVICE_ID__' (expecting 'vpce-svc-...; the Id may only contain "
        "lowercase alphanumeric characters and two dashes')"
    )
    assert info3["message"] == malformed_message, (
        f"expected message {malformed_message!r}, got {info3['message']!r}"
    )
    assert info3["request_id"], "expected a RequestId in ResponseMetadata"


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
