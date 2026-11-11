"""list-search-jobs-reflects-new-job-and-filters-by-status."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-search-jobs-reflects-new-job-and-filters-by-status"
GROUP = "state-machine"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created search job appears in ListSearchJobs (paginating if necessary) with
    matching identifying fields, and ListSearchJobs(ByStatus=<its terminal status>) also
    surfaces it."""
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
        timeout_s=240.0,
        interval_s=3.0,
    )
    terminal_status = final["Status"]

    found = _find_in_pages(bs, job_id)
    assert found is not None, "new search job never appeared in ListSearchJobs"
    assert found["SearchJobArn"] == job_arn, (
        f"SearchJobArn mismatch: listed {found['SearchJobArn']!r}, expected {job_arn!r}"
    )
    assert found["Name"] == name, f"Name mismatch: listed {found['Name']!r}, expected {name!r}"
    assert found["Status"] == terminal_status, (
        f"Status mismatch: listed {found['Status']!r}, expected {terminal_status!r} (from GetSearchJob)"
    )

    found_filtered = _find_in_pages(bs, job_id, by_status=terminal_status)
    assert found_filtered is not None, (
        f"search job missing from ListSearchJobs(ByStatus={terminal_status})"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _find_in_pages(bs, job_id: str, *, by_status=None, max_pages: int = 50):
    kwargs = {"MaxResults": 1000}
    if by_status is not None:
        kwargs["ByStatus"] = by_status
    token = None
    for _ in range(max_pages):
        if token:
            kwargs["NextToken"] = token
        page = bs.list_search_jobs(**kwargs)
        for job in page.get("SearchJobs", []):
            if job["SearchJobIdentifier"] == job_id:
                return job
        token = page.get("NextToken")
        if not token:
            break
    return None


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
