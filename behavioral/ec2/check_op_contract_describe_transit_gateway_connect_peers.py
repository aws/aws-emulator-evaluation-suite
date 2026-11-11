"""op-contract-describe-transit-gateway-connect-peers."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-transit-gateway-connect-peers"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTransitGatewayConnectPeers: listing without IDs succeeds with the
    documented shape; an unrecognized filter name is the distinct error boundary."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_transit_gateway_connect_peers(MaxResults=5)
    assert "TransitGatewayConnectPeers" in resp, f"expected TransitGatewayConnectPeers key, got keys={list(resp.keys())!r}"
    assert isinstance(resp["TransitGatewayConnectPeers"], list), (
        f"expected TransitGatewayConnectPeers to be a list, got {type(resp['TransitGatewayConnectPeers'])!r}"
    )

    code, code_message = _error_code(
        lambda: ec2.describe_transit_gateway_connect_peers(
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
