"""start-search-job-client-token-idempotency."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-search-job-client-token-idempotency"
GROUP = "idempotency"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two identical StartSearchJob calls with one ClientToken return the same SearchJobIdentifier
    and SearchJobArn, and GetSearchJob/ListSearchJobs confirm exactly one search job exists."""
    bs = ctx.client("backupsearch")
    token = str(uuid.uuid4())
    name = ctx.unique_name("sim2real-behav-searchjob-")
    scope = {"BackupResourceTypes": ["S3"]}

    tags_kw = {"Tags": {"sim2real-check": CHECK}}

    first = bs.start_search_job(ClientToken=token, Name=name, SearchScope=scope, **tags_kw)
    job_id = first["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    # Real AWS treats Tags as one of the parameters compared against the first call under
    # the same ClientToken: a repeat with Tags omitted trips ConflictException
    # ("At least one of the input parameters is different from the previous call"), not
    # idempotent replay. The second call must be byte-for-byte identical to the first.
    second = bs.start_search_job(ClientToken=token, Name=name, SearchScope=scope, **tags_kw)

    assert second["SearchJobIdentifier"] == job_id, (
        f"expected repeated ClientToken to echo identifier {job_id!r}, "
        f"got {second['SearchJobIdentifier']!r}"
    )
    assert second["SearchJobArn"] == first["SearchJobArn"], (
        f"expected repeated ClientToken to echo arn {first['SearchJobArn']!r}, "
        f"got {second['SearchJobArn']!r}"
    )

    # Independent read at a different operation: confirm the identifier the second call
    # echoed actually resolves to the same job, not a coincidental collision.
    fetched = bs.get_search_job(SearchJobIdentifier=job_id)
    assert fetched["SearchJobArn"] == first["SearchJobArn"], (
        f"GetSearchJob({job_id}) returned arn {fetched['SearchJobArn']!r}, "
        f"expected {first['SearchJobArn']!r}"
    )

    # Independent read bounding the duplicate: exactly one search job named `name` must
    # exist, proving the second call did not silently create a second underlying job while
    # its response echoed the first job's identifier.
    matches = _find_all_by_name(bs, name)
    assert len(matches) == 1, (
        f"expected exactly one search job named {name!r} after two idempotent StartSearchJob "
        f"calls, found {len(matches)}: {[j['SearchJobIdentifier'] for j in matches]}"
    )
    assert matches[0]["SearchJobIdentifier"] == job_id, (
        f"the sole search job named {name!r} has identifier "
        f"{matches[0]['SearchJobIdentifier']!r}, expected {job_id!r}"
    )


def _find_all_by_name(bs, name: str, *, max_pages: int = 50) -> list:
    matches = []
    kwargs = {"MaxResults": 1000}
    token = None
    for _ in range(max_pages):
        if token:
            kwargs["NextToken"] = token
        page = bs.list_search_jobs(**kwargs)
        matches.extend(j for j in page.get("SearchJobs", []) if j["Name"] == name)
        token = page.get("NextToken")
        if not token:
            break
    return matches


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
