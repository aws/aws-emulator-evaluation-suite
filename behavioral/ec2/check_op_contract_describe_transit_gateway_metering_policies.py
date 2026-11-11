"""op-contract-describeTransitGatewayMeteringPolicies."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeTransitGatewayMeteringPolicies"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTransitGatewayMeteringPolicies returns a well-shaped collection on the
    success path and honors the documented DryRun contract as its error boundary."""
    ec2 = ctx.client("ec2")
    op_name = "describe_transit_gateway_metering_policies"
    if not hasattr(ec2, op_name):
        raise AssertionError(f"{op_name} not available in installed botocore/EC2 model")

    # success path: an unfiltered call must succeed and return a list-shaped collection
    resp = ec2.describe_transit_gateway_metering_policies()
    field, items = _first_list_field(resp)
    assert field is not None, f"no list field found in response: {sorted(resp)}"
    assert isinstance(items, list), f"expected a list-shaped {field!r}, got {type(items)!r}"

    # error boundary: DryRun short-circuits the call with DryRunOperation (documented
    # for every EC2 Describe* action, given sufficient permissions)
    code, code_message = _error_code(lambda: ec2.describe_transit_gateway_metering_policies(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _first_list_field(resp):
    for key, value in resp.items():
        if key == "ResponseMetadata":
            continue
        if isinstance(value, list):
            return key, value
    return None, None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
