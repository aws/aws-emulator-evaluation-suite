"""op-contract-describeCapacityBlockExtensionHistory."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeCapacityBlockExtensionHistory"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityBlockExtensionHistory lists extension events and enforces DryRun."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_capacity_block_extension_history")

    # success path: account-wide listing (no CapacityReservationIds filter); a fresh account
    # has no Capacity Block extensions, which is a valid, well-formed empty result.
    response = ec2.describe_capacity_block_extension_history()
    status = response["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200, got {status!r}"
    assert "CapacityBlockExtensions" in response, (
        f"expected a CapacityBlockExtensions key, got keys {sorted(response)!r}"
    )
    extensions = response["CapacityBlockExtensions"]
    assert isinstance(extensions, list), f"expected CapacityBlockExtensions to be a list, got {extensions!r}"

    # error boundary: DryRun=True must short-circuit with DryRunOperation when the caller has permission
    code, message = _error(lambda: ec2.describe_capacity_block_extension_history(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
