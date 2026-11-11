"""job-list-unknown-queue-returns-empty."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "job-list-unknown-queue-returns-empty"
GROUP = 'error-semantics'
SERVICES = ['batch']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListJobs on a job queue that does not exist succeeds with an empty jobSummaryList; Batch
    raises no not-found error for an unknown queue."""
    bat = ctx.client("batch")
    resp = bat.list_jobs(jobQueue="sim2real-behav-batch-absent-queue")
    jobs = resp.get("jobSummaryList", [])
    assert jobs == [], (
        f"real Batch accepts ListJobs on an unknown queue and returns an empty list, got {jobs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
