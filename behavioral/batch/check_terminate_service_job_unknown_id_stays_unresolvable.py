"""terminate-service-job-unknown-id-stays-unresolvable."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "terminate-service-job-unknown-id-stays-unresolvable"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TerminateServiceJob on an unknown service job id succeeds, and DescribeServiceJob for that
    id then fails with ClientException and the exact not-found message: the call creates no job."""
    batch = ctx.client("batch")
    bogus_job_id = str(uuid.uuid4())

    # Called directly: a rejection raises ClientError and fails the check.
    batch.terminate_service_job(jobId=bogus_job_id, reason="sim2real-negative-probe")

    error = _error(lambda: batch.describe_service_job(jobId=bogus_job_id))
    describe_code, message = error.get("Code"), error.get("Message")
    assert describe_code == "ClientException", (
        "TerminateServiceJob silently accepted an unknown job id; expected the id to remain "
        f"unresolvable via DescribeServiceJob, got {describe_code!r}"
    )
    assert message == _describe_unknown_message(ctx, bogus_job_id), (
        f"expected the exact DescribeServiceJob unknown-id message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _describe_unknown_message(ctx, job_id):
    """The exact message DescribeServiceJob returns for a service job id that does not exist."""
    return f"arn:aws:batch:{ctx.region}:{ctx.account}:service-job/{job_id} does not exist"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
