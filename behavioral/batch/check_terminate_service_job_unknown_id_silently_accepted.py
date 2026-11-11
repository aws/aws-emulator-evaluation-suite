"""terminate-service-job-unknown-id-silently-accepted."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-service-job-unknown-id-silently-accepted"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateJob and TerminateServiceJob on unknown well-formed ids both succeed as no-ops:
    DescribeJobs then returns [] for the job id, and DescribeServiceJob fails with ClientException
    and the exact not-found message for the service job id."""
    batch = ctx.client("batch")

    # TerminateJob on an unknown (but well-formed) job id is accepted silently
    # -- it does not raise.
    bogus_job_id = str(uuid.uuid4())
    # Called directly: a rejection raises ClientError and fails the check.
    batch.terminate_job(jobId=bogus_job_id, reason="sim2real-behavioral-check probe")

    # "accepted" must not mean "materialized" -- the plural DescribeJobs read
    # (an independent operation from the terminate call above) must still show
    # no job for this id, not a fabricated record.
    describe_resp = batch.describe_jobs(jobs=[bogus_job_id])
    assert describe_resp["jobs"] == [], (
        f"TerminateJob on an unknown jobId produced a describable job: {describe_resp['jobs']!r}"
    )

    # the service-job equivalent, for an unknown service job id, behaves the
    # same way: accepted silently, no ClientException raised.
    bogus_service_job_id = str(uuid.uuid4())
    batch.terminate_service_job(jobId=bogus_service_job_id, reason="sim2real-behavioral-check probe")

    # same independent-read requirement for the service-job side: DescribeServiceJob
    # is a distinct operation from TerminateServiceJob, and must still report the id
    # as unresolvable rather than having conjured a job record into existence.
    error = _error(lambda: batch.describe_service_job(jobId=bogus_service_job_id))
    describe_code, message = error.get("Code"), error.get("Message")
    assert describe_code == "ClientException", (
        "TerminateServiceJob on an unknown jobId produced a describable service job, expected "
        f"DescribeServiceJob to raise ClientException, got code={describe_code!r}"
    )
    assert message == _describe_unknown_message(ctx, bogus_service_job_id), (
        f"expected the exact DescribeServiceJob unknown-id message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
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
