"""op-contract-describe-transit-gateway-attachments."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-transit-gateway-attachments"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTransitGatewayAttachments: listing without IDs succeeds with the
    documented shape; an unrecognized filter name is the distinct error boundary."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_transit_gateway_attachments(MaxResults=5)
    assert "TransitGatewayAttachments" in resp, (
        f"expected a TransitGatewayAttachments key in the response, got keys {sorted(resp)!r}"
    )
    assert isinstance(resp["TransitGatewayAttachments"], list), (
        f"expected TransitGatewayAttachments to be a list, got "
        f"{type(resp['TransitGatewayAttachments']).__name__}"
    )

    code, code_message = _error_code(
        lambda: ec2.describe_transit_gateway_attachments(
            Filters=[{"Name": "not-a-real-filter", "Values": ["x"]}]
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_code_message = "Value (not-a-real-filter) for parameter Filter is invalid. "
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
