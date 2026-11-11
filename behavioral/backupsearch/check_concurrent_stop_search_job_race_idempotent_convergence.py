"""concurrent-stop-search-job-race-idempotent-convergence."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-stop-search-job-race-idempotent-convergence"
GROUP = "concurrency"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent StopSearchJob calls racing against the same RUNNING search job both
    succeed (StopSearchJob is idempotent, not exclusive) and the job converges on exactly one
    terminal state: STOPPED."""
    bs = ctx.client("backupsearch")
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    def _attempt(_i):
        from botocore.exceptions import ClientError

        try:
            bs.stop_search_job(SearchJobIdentifier=job_id)
            return ("ok", None)
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(_attempt, range(2)))

    winners = [o for o in outcomes if o[0] == "ok"]
    losers = [o for o in outcomes if o[0] == "error"]
    assert len(winners) == 2, f"expected both concurrent stop calls to succeed (idempotent), got {outcomes}"
    assert len(losers) == 0, f"expected no rejected stop call, got {outcomes}"

    final = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=job_id),
        lambda r: r["Status"] in ("STOPPED", "COMPLETED", "FAILED"),
        timeout_s=120.0,
        interval_s=2.0,
    )
    assert final["Status"] == "STOPPED", f"job did not converge on STOPPED: {final}"


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
    try:
        bs.stop_search_job(SearchJobIdentifier=job_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

