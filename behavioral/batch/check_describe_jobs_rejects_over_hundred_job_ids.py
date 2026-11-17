"""describe-jobs-rejects-over-hundred-job-ids."""
from __future__ import annotations

import uuid
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


CHECK = "describe-jobs-rejects-over-hundred-job-ids"
GROUP = "validation"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeJobs rejects a jobs list longer than 100 entries with ClientException; a list of
    exactly 100 job IDs is accepted and unknown job IDs are simply absent from the result."""
    batch = ctx.client("batch")
    over_limit = [str(uuid.uuid4()) for _ in range(101)]

    code, message, request_id = _error_code(lambda: batch.describe_jobs(jobs=over_limit))
    assert code == "ClientException", f"expected ClientException for 101 job IDs, got {code!r}"
    expected_message = (
        "Error executing request, Exception : Maximum number of jobs supported is  100 ., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: exactly 100 job IDs (none of which exist) is accepted.
    at_limit = over_limit[:100]
    accepted = batch.describe_jobs(jobs=at_limit)
    assert accepted["jobs"] == [], f"expected no jobs for unknown IDs, got {accepted['jobs']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
