"""terminate-jobs-rejects-over-fifty-jobs."""
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


CHECK = "terminate-jobs-rejects-over-fifty-jobs"
GROUP = "validation"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TerminateJobs rejects a jobs list longer than 50 entries with ClientException; a list of
    exactly 50 unknown job IDs is accepted and every one is reported successful."""
    batch = ctx.client("batch")
    over_limit = [str(uuid.uuid4()) for _ in range(51)]

    code, message, request_id = _error_code(
        lambda: batch.terminate_jobs(jobs=over_limit, reason="sim2real test termination")
    )
    assert code == "ClientException", f"expected ClientException for 51 job IDs, got {code!r}"
    expected_message = (
        "Error executing request, Exception : A maximum of 50 jobs can be specified per request., "
        f"RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: exactly 50 job IDs (none of which exist) is accepted; unknown jobs are
    # treated as already terminated.
    at_limit = over_limit[:50]
    accepted = batch.terminate_jobs(jobs=at_limit, reason="sim2real test termination")
    assert sorted(accepted["successful"]) == sorted(at_limit), (
        f"expected all 50 unknown job IDs reported successful, got {accepted!r}"
    )
    assert accepted["errors"] == [], f"expected no errors for unknown job IDs, got {accepted['errors']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
