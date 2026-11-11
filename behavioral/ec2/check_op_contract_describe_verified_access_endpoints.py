"""op-contract-describeVerifiedAccessEndpoints."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeVerifiedAccessEndpoints"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVerifiedAccessEndpoints returns a well-shaped collection on the
    success path and honors the documented DryRun contract as its error boundary."""
    ec2 = ctx.client("ec2")
    op_name = "describe_verified_access_endpoints"
    if not hasattr(ec2, op_name):
        raise AssertionError(f"{op_name} not available in installed botocore/EC2 model")

    field = _collection_field(ec2, "DescribeVerifiedAccessEndpoints")
    resp = ec2.describe_verified_access_endpoints()
    assert field in resp, f"response missing modeled field {field!r}: {sorted(resp)}"
    items = resp[field]
    assert isinstance(items, list), f"{field!r} is a {type(items).__name__}, not a list"

    code, message = _client_error(lambda: ec2.describe_verified_access_endpoints(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_message = "Request would have succeeded, but DryRun flag is set."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _collection_field(client, op_name: str) -> str:
    """The output shape's list-typed member name, read from the client's own service
    model instead of hardcoded -- avoids a stale guess if the member is ever renamed."""
    output = client.meta.service_model.operation_model(op_name).output_shape
    for name, shape in output.members.items():
        if shape.type_name == "list":
            return name
    raise AssertionError(f"{op_name} output shape has no list member: {sorted(output.members)}")


def _client_error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
