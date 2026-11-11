"""job-cancel-unknown-id-is-a-no-op."""

from __future__ import annotations
import uuid

from behavioral_harness import tags


CHECK = "job-cancel-unknown-id-is-a-no-op"
GROUP = 'error-semantics'
SERVICES = ['batch']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelJob and TerminateJob on a well-formed unknown jobId both succeed, and DescribeJobs
    returns [] for that id after each: both calls are idempotent no-ops that create no job."""
    bat = ctx.client("batch")
    bogus = str(uuid.uuid4())

    # Real Batch accepts CancelJob for an unknown jobId (idempotent no-op): a raise here fails the check.
    bat.cancel_job(jobId=bogus, reason="fidelity-check")
    after_cancel = bat.describe_jobs(jobs=[bogus])["jobs"]
    assert after_cancel == [], (
        f"CancelJob on an unknown jobId must not fabricate a job; describe_jobs returned {after_cancel!r}"
    )

    # Real Batch accepts TerminateJob for an unknown jobId (idempotent no-op): a raise here fails the check.
    bat.terminate_job(jobId=bogus, reason="fidelity-check")
    after_terminate = bat.describe_jobs(jobs=[bogus])["jobs"]
    assert after_terminate == [], (
        f"TerminateJob on an unknown jobId must not fabricate a job; describe_jobs returned {after_terminate!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
