"""stop-search-job-idempotent-when-already-stopped."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-search-job-idempotent-when-already-stopped"
GROUP = "state-machine"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopSearchJob is idempotent: calling it again on a search job that is already STOPPED
    succeeds (HTTP 200, no ConflictException) rather than being rejected, and the job's status
    remains STOPPED, unchanged by the redundant call."""
    bs = ctx.client("backupsearch")
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
        Tags={"sim2real-behav": CHECK},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    # First stop drives the job to STOPPED.
    bs.stop_search_job(SearchJobIdentifier=job_id)
    stopped = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=job_id),
        lambda r: r["Status"] in ("STOPPED", "COMPLETED", "FAILED"),
        timeout_s=120.0,
        interval_s=2.0,
    )
    assert stopped["Status"] == "STOPPED", f"first stop did not reach STOPPED: {stopped}"

    # Second stop on the already-STOPPED job is a no-op success, not a conflict.
    result, code = _error_code_or_result(lambda: bs.stop_search_job(SearchJobIdentifier=job_id))
    assert code is None, f"expected idempotent success, got error code={code}"
    status_code = result["ResponseMetadata"]["HTTPStatusCode"]
    assert status_code == 200, f"expected HTTP 200 on redundant stop, got {status_code}"

    # Status is still STOPPED, unaffected by the redundant call.
    after = bs.get_search_job(SearchJobIdentifier=job_id)
    assert after["Status"] == "STOPPED", f"redundant stop must not change status: {after!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _error_code_or_result(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
        return result, None
    except ClientError as err:
        return None, err.response["Error"]["Code"]


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


