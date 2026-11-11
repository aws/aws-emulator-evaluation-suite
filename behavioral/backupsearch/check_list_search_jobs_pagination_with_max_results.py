"""list-search-jobs-pagination-with-max-results."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-search-jobs-pagination-with-max-results"
GROUP = "pagination"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With at least two search jobs known to exist, ListSearchJobs(MaxResults=1) returns
    exactly one item per page and a NextToken that can be used to retrieve a distinct next
    page."""
    bs = ctx.client("backupsearch")
    job_ids = []
    for _ in range(2):
        started = bs.start_search_job(
            Name=ctx.unique_name("sim2real-behav-searchjob-"),
            SearchScope={"BackupResourceTypes": ["S3"]},
            Tags={"sim2real-behav": "list-search-jobs-pagination-with-max-results"},
        )
        job_ids.append(started["SearchJobIdentifier"])
    for jid in job_ids:
        ctx.on_cleanup(lambda jid=jid: _best_effort_stop(bs, jid))

    page1 = bs.list_search_jobs(MaxResults=1)
    assert len(page1["SearchJobs"]) == 1, (
        f"expected exactly 1 job with MaxResults=1, got {len(page1['SearchJobs'])}"
    )
    next_token = page1.get("NextToken")
    assert next_token, "expected a NextToken with >= 2 search jobs known to exist and MaxResults=1"

    page2 = bs.list_search_jobs(MaxResults=1, NextToken=next_token)
    assert len(page2["SearchJobs"]) == 1, (
        f"NextToken promised a further page but page2 returned "
        f"{len(page2['SearchJobs'])} items"
    )
    assert page2["SearchJobs"][0]["SearchJobIdentifier"] != page1["SearchJobs"][0]["SearchJobIdentifier"], (
        "page2 returned the same SearchJobIdentifier as page1"
    )


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
