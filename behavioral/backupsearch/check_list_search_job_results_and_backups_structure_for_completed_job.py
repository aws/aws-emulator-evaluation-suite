"""list-search-job-results-and-backups-structure-for-completed-job."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-search-job-results-and-backups-structure-for-completed-job"
GROUP = "data-plane"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A search job scoped to a never-backed-up bucket ARN FAILS like an empty scope: the
    StatusMessage names the empty scope, all scan counts are zero and the backups/results pages are empty."""
    bs = ctx.client("backupsearch")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-bsjobsrc-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _best_effort_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )
    bucket_arn = f"arn:aws:s3:::{bucket}"

    name = ctx.unique_name("sim2real-behav-searchjob-")
    started = bs.start_search_job(
        Name=name,
        SearchScope={"BackupResourceTypes": ["S3"], "SourceResourceArns": [bucket_arn]},
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
    # A resource ARN with zero backing recovery points fails the
    # SAME way as a scope with no ARNs at all ("Search scope is empty..."), not with COMPLETED
    # and an empty page.
    assert final["Status"] == "FAILED", f"expected empty-scope refusal, got: {final!r}"
    assert "empty" in final.get("StatusMessage", "").lower(), (
        f"expected StatusMessage to name the empty scope, got: {final.get('StatusMessage')!r}"
    )
    scope_summary = final.get("SearchScopeSummary", {})
    assert scope_summary.get("TotalRecoveryPointsToScanCount") == 0, (
        f"expected zero recovery points to scan for an unbacked resource, got: {scope_summary!r}"
    )
    assert scope_summary.get("TotalItemsToScanCount") == 0, (
        f"expected zero items to scan for an unbacked resource, got: {scope_summary!r}"
    )
    progress = final.get("CurrentSearchProgress", {})
    assert progress.get("RecoveryPointsScannedCount") == 0, (
        f"expected zero recovery points scanned, got: {progress!r}"
    )
    assert progress.get("ItemsScannedCount") == 0, f"expected zero items scanned, got: {progress!r}"
    assert progress.get("ItemsMatchedCount") == 0, f"expected zero items matched, got: {progress!r}"
    assert final["Name"] == name, f"expected echoed Name={name!r}, got {final.get('Name')!r}"
    assert final["SearchJobIdentifier"] == job_id, (
        f"expected echoed SearchJobIdentifier={job_id!r}, got {final.get('SearchJobIdentifier')!r}"
    )
    assert final["SearchJobArn"] == job_arn, (
        f"expected echoed SearchJobArn={job_arn!r}, got {final.get('SearchJobArn')!r}"
    )
    assert "CreationTime" in final, f"missing CreationTime on terminal record: {final!r}"
    if "CompletionTime" in final:
        assert final["CompletionTime"] >= final["CreationTime"], (
            f"CompletionTime {final['CompletionTime']!r} precedes "
            f"CreationTime {final['CreationTime']!r}: {final!r}"
        )

    backups = bs.list_search_job_backups(SearchJobIdentifier=job_id)["Results"]
    assert backups == [], f"expected an empty backups page for an unscanned resource, got: {backups!r}"
    for entry in backups:
        if "Status" in entry:
            assert entry["Status"] in ("RUNNING", "COMPLETED", "STOPPING", "STOPPED", "FAILED"), (
                f"backups entry Status not in documented enum: {entry!r}"
            )
        if "ResourceType" in entry:
            assert entry["ResourceType"] in ("S3", "EBS"), (
                f"backups entry ResourceType not in documented enum: {entry!r}"
            )

    results = bs.list_search_job_results(SearchJobIdentifier=job_id)["Results"]
    assert results == [], f"expected an empty results page for an unscanned resource, got: {results!r}"
    for entry in results:
        present = [k for k in ("S3ResultItem", "EBSResultItem") if k in entry]
        assert len(present) == 1, f"expected exactly one result-item union member, got {entry!r}"


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


def _best_effort_delete_bucket(s3, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
