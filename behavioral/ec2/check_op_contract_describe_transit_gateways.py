"""op-contract-describeTransitGateways."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeTransitGateways"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTransitGateways returns a well-shaped collection on the success path
    and honors the documented DryRun contract as its error boundary."""
    ec2 = ctx.client("ec2")
    op_name = "describe_transit_gateways"
    if not hasattr(ec2, op_name):
        raise AssertionError(f"{op_name} not available in installed botocore/EC2 model")

    resp = ec2.describe_transit_gateways()
    field, items = _first_list_field(resp)
    assert field is not None, f"no list field found in response: {sorted(resp)}"
    assert isinstance(items, list), f"expected list field {field!r} to be a list, got {type(items)!r}"

    # Filters-based lookup on a bogus (but well-formed) transit-gateway-id must
    # deterministically return an empty collection rather than error
    resp_filtered = ec2.describe_transit_gateways(
        Filters=[{"Name": "transit-gateway-id", "Values": ["tgw-00000000000000000"]}]
    )
    _, filtered_items = _first_list_field(resp_filtered)
    assert filtered_items == [], f"expected empty filtered result, got {filtered_items}"

    code, message = _client_error(lambda: ec2.describe_transit_gateways(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_message = "Request would have succeeded, but DryRun flag is set."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
