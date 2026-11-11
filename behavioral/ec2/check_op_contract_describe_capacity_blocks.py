"""op-contract-describeCapacityBlocks."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeCapacityBlocks"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityBlocks lists Capacity Block details and enforces DryRun."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_capacity_blocks")

    # success path: account-wide listing (no CapacityBlockIds filter); a fresh account has no
    # Capacity Blocks, which is a valid, well-formed empty result.
    response = ec2.describe_capacity_blocks()
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected HTTP 200, got {response['ResponseMetadata']!r}"
    )
    # substantive assertion directly on the response body (confirmed shape: top-level
    # "CapacityBlocks" list -- see the CLI Output section / --query hint for
    # describe-capacity-blocks).
    assert "CapacityBlocks" in response, f"expected CapacityBlocks in response body: {response!r}"
    blocks = response["CapacityBlocks"]
    assert isinstance(blocks, list), f"expected CapacityBlocks to be a list, got {blocks!r}"
    for item in blocks:
        assert isinstance(item, dict), f"Capacity Block record should be dict-shaped, got {item!r}"
        # a Capacity Block record should identify itself and its lifecycle state
        assert "CapacityBlockId" in item or "State" in item, (
            f"Capacity Block record missing CapacityBlockId/State: {item!r}"
        )
    if not blocks:
        # pagination contract: nextToken must be null/absent when there is nothing more to return
        assert response.get("NextToken") in (None, ""), (
            "NextToken should be empty/absent when the result set is empty"
        )

    # error boundary: DryRun=True must short-circuit with DryRunOperation when the caller has permission
    code, message = _error(lambda: ec2.describe_capacity_blocks(DryRun=True))
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
