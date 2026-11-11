"""op-contract-describe-transit-gateway-connects."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-transit-gateway-connects"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTransitGatewayConnects answers with a list, and a filter on an unknown attachment ID
    returns none; DryRun answers DryRunOperation and an unrecognized filter name fails with
    InvalidParameterValue, each with its exact message."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_transit_gateway_connects(MaxResults=5)
    assert "TransitGatewayConnects" in resp
    assert isinstance(resp["TransitGatewayConnects"], list)

    # Filters-based lookup on a bogus (but well-formed) attachment id must deterministically
    # return an empty collection rather than error.
    resp_filtered = ec2.describe_transit_gateway_connects(
        Filters=[{"Name": "transit-gateway-attachment-id", "Values": ["tgw-attach-00000000000000000"]}]
    )
    assert resp_filtered["TransitGatewayConnects"] == [], (
        f"expected empty filtered result, got {resp_filtered['TransitGatewayConnects']}"
    )

    code, code_message = _error_code(lambda: ec2.describe_transit_gateway_connects(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    code, code_message = _error_code(
        lambda: ec2.describe_transit_gateway_connects(
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
