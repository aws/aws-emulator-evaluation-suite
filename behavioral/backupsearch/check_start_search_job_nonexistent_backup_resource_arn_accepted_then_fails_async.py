"""start-search-job-nonexistent-backup-resource-arn-accepted-then-fails-async."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-search-job-nonexistent-backup-resource-arn-accepted-then-fails-async"
GROUP = "state-machine"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSearchJob accepts a nonexistent recovery-point ARN without synchronous validation;
    the job then FAILS asynchronously with the empty-scope StatusMessage and zero items to scan."""
    bs = ctx.client("backupsearch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_rp_arn = (
        f"arn:aws:backup:{ctx.region}:{account_id}:recovery-point:"
        "00000000-0000-0000-0000-000000000000"
    )

    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={
            "BackupResourceTypes": ["S3"],
            "BackupResourceArns": [bogus_rp_arn],
        },
        Tags={"sim2real-check": CHECK},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))
    assert job_id

    # The bogus-ARN job resolves to a terminal state (not left hanging in RUNNING forever).
    final = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=job_id),
        lambda r: r["Status"] in ("COMPLETED", "FAILED", "STOPPED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final["Status"] == "FAILED", (
        f"expected the bogus-ARN job to resolve to FAILED (empty scope), got: {final!r}"
    )
    assert "empty" in final.get("StatusMessage", "").lower(), final.get("StatusMessage")
    summary = final.get("SearchScopeSummary", {})
    assert summary.get("TotalRecoveryPointsToScanCount") == 0, summary
    assert summary.get("TotalItemsToScanCount") == 0, summary

    # Positive control: the same scope minus the nonexistent ARN reference is accepted too.
    control_started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
        Tags={"sim2real-check": CHECK},
    )
    control_job_id = control_started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, control_job_id))
    assert control_job_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _best_effort_stop(bs, job_id: str) -> None:
    # A job already in a terminal state answers StopSearchJob with ConflictException: nothing to stop.
    try:
        bs.stop_search_job(SearchJobIdentifier=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        terminal = ("COMPLETED", "FAILED", "STOPPED", "STOPPING")
        if code == "ConflictException" and bs.get_search_job(SearchJobIdentifier=job_id)["Status"] in terminal:
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

