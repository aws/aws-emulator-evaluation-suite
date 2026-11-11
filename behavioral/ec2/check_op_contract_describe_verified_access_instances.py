"""op-contract-describeVerifiedAccessInstances."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeVerifiedAccessInstances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVerifiedAccessInstances returns the documented VerifiedAccessInstances
    collection on the success path and honors the documented DryRun contract as its
    error boundary."""
    ec2 = ctx.client("ec2")
    op_name = "describe_verified_access_instances"
    if not hasattr(ec2, op_name):
        raise AssertionError(f"{op_name} not available in installed botocore/EC2 model")

    resp = ec2.describe_verified_access_instances()
    assert "VerifiedAccessInstances" in resp, (
        f"expected a VerifiedAccessInstances field in the response, got keys {sorted(resp)}"
    )
    items = resp["VerifiedAccessInstances"]
    assert isinstance(items, list), f"expected VerifiedAccessInstances to be a list, got {items!r}"

    error = _client_error(lambda: ec2.describe_verified_access_instances(DryRun=True))
    code = error.get("Code")
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r} ({error!r})"
    expected_message = "Request would have succeeded, but DryRun flag is set."
    message = error.get("Message")
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected DryRun=True to be rejected with DryRunOperation, but the call "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
