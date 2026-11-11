"""terminate-unknown-job-is-accepted."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "terminate-unknown-job-is-accepted"
GROUP = 'error-semantics'
SERVICES = ['batch']

def _call(fn):
    """Call fn(); return (response, error code). error code is None on success, response is None on error."""
    try:
        return fn(), None
    except ClientError as exc:
        return None, exc.response.get("Error", {}).get("Code")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateJob on a well-formed unknown jobId succeeds with an empty body, and DescribeJobs
    then returns [] for that id: the idempotent call raises no not-found error and creates no job."""
    bat = ctx.client("batch")
    bogus_job_id = "00000000-0000-0000-0000-000000000000"

    resp, code = _call(lambda: bat.terminate_job(
        jobId=bogus_job_id,
        reason="behavioral-test-unknown-job",
    ))
    assert code is None, (
        f"real Batch accepts TerminateJob for an unknown jobId (idempotent no-op), got {code!r}"
    )
    body = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
    assert body == {}, f"TerminateJob on an unknown jobId must return an empty body, got {body!r}"

    # Independent read at the destination (DescribeJobs, not the mutating call's own
    # response): accepting the call must not have manifested a job record as a side effect.
    jobs = bat.describe_jobs(jobs=[bogus_job_id])["jobs"]
    assert jobs == [], f"TerminateJob on an unknown jobId must not create a job record, got {jobs!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
