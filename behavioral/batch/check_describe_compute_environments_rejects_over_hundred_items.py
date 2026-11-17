"""describe-compute-environments-rejects-over-hundred-items."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


CHECK = "describe-compute-environments-rejects-over-hundred-items"
GROUP = "validation"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeComputeEnvironments rejects a computeEnvironments list longer than 100 entries
    with ClientException; a list of exactly 100 unknown names is accepted and returns none."""
    batch = ctx.client("batch")
    prefix = ctx.unique_name("sim2real-batch-ce-missing-")
    over_limit = [f"{prefix}-{i}" for i in range(101)]

    code, message, request_id = _error_code(
        lambda: batch.describe_compute_environments(computeEnvironments=over_limit)
    )
    assert code == "ClientException", f"expected ClientException for 101 names, got {code!r}"
    expected_message = (
        "Error executing request, Exception : Number of compute environments should be between "
        f"1 and 100., RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: exactly 100 unknown names is accepted and returns none of them.
    at_limit = over_limit[:100]
    accepted = batch.describe_compute_environments(computeEnvironments=at_limit)
    assert accepted["computeEnvironments"] == [], (
        f"expected no compute environments for unknown names, got {accepted['computeEnvironments']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
