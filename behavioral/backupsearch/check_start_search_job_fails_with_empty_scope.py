"""start-search-job-fails-with-empty-scope."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-search-job-fails-with-empty-scope"
GROUP = "state-machine"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A search job with a resource type but no BackupResourceArns has nothing to scan: it ends
    FAILED (not COMPLETED) with a StatusMessage naming the empty scope and empty results/backups pages."""
    bs = ctx.client("backupsearch")
    name = ctx.unique_name("sim2real-behav-searchjob-")
    started = bs.start_search_job(
        Name=name,
        SearchScope={"BackupResourceTypes": ["S3"]},
        Tags={"sim2real": CHECK},
    )
    job_id = started["SearchJobIdentifier"]
    job_arn = started["SearchJobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    final = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=job_id),
        lambda r: r["Status"] in ("COMPLETED", "FAILED", "STOPPED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final["Status"] == "FAILED", f"expected empty scope to fail, got: {final!r}"
    assert final["Name"] == name, f"expected echoed Name={name!r}, got {final.get('Name')!r}"
    assert final["SearchJobIdentifier"] == job_id, (
        f"expected echoed SearchJobIdentifier={job_id!r}, got {final.get('SearchJobIdentifier')!r}"
    )
    assert final["SearchJobArn"] == job_arn, (
        f"expected echoed SearchJobArn={job_arn!r}, got {final.get('SearchJobArn')!r}"
    )
    assert "empty" in final.get("StatusMessage", "").lower(), (
        f"expected StatusMessage to name the empty scope, got: {final.get('StatusMessage')!r}"
    )
    assert "CreationTime" in final, f"missing CreationTime on terminal record: {final!r}"
    if "CompletionTime" in final:
        assert final["CompletionTime"] >= final["CreationTime"], (
            f"CompletionTime {final['CompletionTime']!r} precedes "
            f"CreationTime {final['CreationTime']!r}: {final!r}"
        )
    assert final["SearchScope"]["BackupResourceTypes"] == ["S3"], (
        f"expected echoed SearchScope.BackupResourceTypes=['S3'], got: {final.get('SearchScope')!r}"
    )

    # Effect-scoped: a FAILED job still exposes well-formed (empty) results/backups pages.
    results = bs.list_search_job_results(SearchJobIdentifier=job_id)["Results"]
    assert results == [], f"expected an empty results page for a FAILED job, got: {results!r}"
    backups = bs.list_search_job_backups(SearchJobIdentifier=job_id)["Results"]
    assert backups == [], f"expected an empty backups page for a FAILED job, got: {backups!r}"


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

