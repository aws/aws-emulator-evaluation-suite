"""op-contract-assignIpv6Addresses-b."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-assignIpv6Addresses-b"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssignIpv6Addresses on a well-formed nonexistent network interface id fails
    InvalidNetworkInterfaceID.NotFound, and on a malformed id fails
    InvalidNetworkInterfaceId.Malformed, each with its exact message and a RequestId.
    """
    ec2 = ctx.client("ec2")
    fake_eni_id = "eni-0fedcba987654321f"
    malformed_eni_id = "not-an-eni-id"

    info = _client_error_info(
        lambda: ec2.assign_ipv6_addresses(
            NetworkInterfaceId=fake_eni_id, Ipv6AddressCount=1
        )
    )
    assert info["code"] == "InvalidNetworkInterfaceID.NotFound", (
        f"expected InvalidNetworkInterfaceID.NotFound, got {info['code']!r}"
    )
    expected = f"The networkInterface ID '{fake_eni_id}' does not exist"
    assert info["message"] == expected, f"expected message {expected!r}, got {info['message']!r}"
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    # discriminating control: a malformed (not merely nonexistent) network interface id is
    # rejected on a distinct boundary, so NotFound for every input cannot pass.
    malformed_info = _client_error_info(
        lambda: ec2.assign_ipv6_addresses(
            NetworkInterfaceId=malformed_eni_id, Ipv6AddressCount=1
        )
    )
    assert malformed_info["code"] != "InvalidNetworkInterfaceID.NotFound", (
        "a malformed id must not be classified identically to a well-formed but "
        f"nonexistent one, got {malformed_info['code']!r} for both"
    )
    assert malformed_info["code"] == "InvalidNetworkInterfaceId.Malformed", (
        f"expected InvalidNetworkInterfaceId.Malformed for a malformed id, "
        f"got {malformed_info['code']!r}"
    )
    expected_malformed = f"The interface ID '{malformed_eni_id}' is malformed"
    assert malformed_info["message"] == expected_malformed, (
        f"expected message {expected_malformed!r}, got {malformed_info['message']!r}"
    )
    assert malformed_info["request_id"], "expected a RequestId in ResponseMetadata"


def _client_error_info(fn):
    """Call fn(); return its error code/message/RequestId. An unexpected SUCCESS raises,
    because a target ACCEPTING input real AWS refuses must not read as a code mismatch."""
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
