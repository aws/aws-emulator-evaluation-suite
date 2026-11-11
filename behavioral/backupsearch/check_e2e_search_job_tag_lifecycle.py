"""e2e-search-job-tag-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-search-job-tag-lifecycle"
GROUP = "e2e"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A search job is listed, tagged, untagged and resolves to FAILED for an empty scope;
    StopSearchJob on the FAILED job is rejected with ConflictException and leaves it FAILED."""
    bs = ctx.client("backupsearch")
    name = ctx.unique_name("sim2real-behav-searchjob-")
    started = bs.start_search_job(Name=name, SearchScope={"BackupResourceTypes": ["S3"]})
    job_id = started["SearchJobIdentifier"]
    job_arn = started["SearchJobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    # Step 1: the job is discoverable via ListSearchJobs immediately after creation.
    found = _poll_until(
        lambda: bs.list_search_jobs().get("SearchJobs", []),
        lambda jobs: any(j["SearchJobIdentifier"] == job_id for j in jobs),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert any(j["SearchJobIdentifier"] == job_id for j in found), (
        f"expected {job_id!r} in ListSearchJobs, got {[j.get('SearchJobIdentifier') for j in found]!r}"
    )

    # Step 2: tag the freshly created job and confirm the tag round-trips.
    bs.tag_resource(ResourceArn=job_arn, Tags={"sim2real-e2e": "lifecycle"})
    tags = bs.list_tags_for_resource(ResourceArn=job_arn)
    assert tags["Tags"] == {"sim2real-e2e": "lifecycle"}, (
        f"expected tag round-trip via ListTagsForResource, got {tags['Tags']!r}"
    )

    # Step 3: the job (started with an empty resource scope) resolves to a terminal state.
    final = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=job_id),
        lambda r: r["Status"] in ("COMPLETED", "FAILED", "STOPPED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final["Status"] == "FAILED", f"expected empty-scope job to fail, got {final!r}"

    # Step 4: StopSearchJob rejects a job that is already FAILED (distinct from the
    # STOPPED-already-STOPPED case, which is a harmless idempotent no-op): FAILED is not stoppable.
    code, message = _client_error(lambda: bs.stop_search_job(SearchJobIdentifier=job_id))
    assert code == "ConflictException", f"expected ConflictException stopping a FAILED job, got code={code!r}"
    assert message == "SearchJob can not be stopped since it is in FAILED state. Please try again later", (
        f"unexpected message {message!r}"
    )
    after_stop = bs.get_search_job(SearchJobIdentifier=job_id)
    assert after_stop["Status"] == "FAILED", f"rejected stop must not alter a FAILED job: {after_stop!r}"

    # Step 5: remove the tag and confirm it is gone, without disturbing the resource itself.
    bs.untag_resource(ResourceArn=job_arn, TagKeys=["sim2real-e2e"])
    tags_after = bs.list_tags_for_resource(ResourceArn=job_arn)
    assert tags_after.get("Tags", {}) == {}, f"expected no tags after untag, got {tags_after.get('Tags')!r}"
    still_there = bs.get_search_job(SearchJobIdentifier=job_id)
    assert still_there["SearchJobIdentifier"] == job_id, (
        f"expected the job to still exist after untagging, got {still_there!r}"
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


def _client_error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

