"""start-search-result-export-job-immediately-after-start-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-search-result-export-job-immediately-after-start-rejected"
GROUP = "overly-permissive"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSearchResultExportJob on a search job that is neither COMPLETED nor STOPPED is rejected
    with a ValidationException naming its status and creates no export job; the same request
    succeeds once a job is STOPPED."""
    bs = ctx.client("backupsearch")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-bksearch-export-").lower()
    _create_bucket(ctx, s3, bucket)
    export_spec = {"s3ExportSpecification": {"DestinationBucket": bucket}}

    # --- Break: a job scoped to a bucket no recovery point backs is CREATING or RUNNING right
    # after StartSearchJob and then FAILS for its empty scope; none of those statuses permits an
    # export, so the refusal holds whenever the export call lands.
    running_job = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-running-"),
        SearchScope={"BackupResourceTypes": ["S3"], "SourceResourceArns": [f"arn:aws:s3:::{bucket}"]},
        Tags={"sim2real": CHECK},
    )
    running_job_id = running_job["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, running_job_id))
    before = bs.get_search_job(SearchJobIdentifier=running_job_id)["Status"]
    assert before in ("CREATING", "RUNNING", "FAILED"), f"expected a freshly started job, got {before!r}"

    code, message = _client_error(
        lambda: bs.start_search_result_export_job(
            SearchJobIdentifier=running_job_id, ExportSpecification=export_spec
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException (export gated on COMPLETED/STOPPED status), got code={code!r}"
    )
    # The message names the status the export path read, which can trail the GetSearchJob
    # status (CREATING while GetSearchJob already reports RUNNING).
    expected = [
        "Export is only supported for search job with COMPLETED,STOPPED statuses. "
        f"SearchJob has status {status}. Please try again later"
        for status in ("CREATING", "RUNNING", "FAILED")
    ]
    assert message in expected, f"expected one of {expected!r}, got {message!r}"

    # Effect absent: the rejected call created no export job.
    exports = bs.list_search_result_export_jobs(SearchJobIdentifier=running_job_id)
    assert exports["ExportJobs"] == [], (
        f"expected no export jobs after rejection, got {exports['ExportJobs']!r}"
    )

    # The search job resource itself is still normally readable.
    still_running = bs.get_search_job(SearchJobIdentifier=running_job_id)
    assert still_running["SearchJobIdentifier"] == running_job_id, (
        f"expected search job {running_job_id} still independently readable, got {still_running!r}"
    )

    # --- Restore: a dedicated second job, stopped with no intervening call so it cannot race
    # this account's empty-scope job to a natural FAILED (which does not permit export either),
    # accepts the identical export request once it reaches STOPPED.
    stoppable_job = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-stopped-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
        Tags={"sim2real": CHECK},
    )
    stoppable_job_id = stoppable_job["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, stoppable_job_id))
    bs.stop_search_job(SearchJobIdentifier=stoppable_job_id)
    stopped = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=stoppable_job_id),
        lambda r: r["Status"] in ("COMPLETED", "FAILED", "STOPPED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert stopped["Status"] == "STOPPED", f"setup did not reach STOPPED: {stopped!r}"

    control = bs.start_search_result_export_job(
        SearchJobIdentifier=stoppable_job_id, ExportSpecification=export_spec
    )
    assert control["ExportJobIdentifier"], (
        f"expected the identical export call to succeed once job reached STOPPED, got {control!r}"
    )

    # Terminal independent read at the destination: the accepted export job is now visible
    # through ListSearchResultExportJobs, a different operation than the one that created it.
    exports_after = bs.list_search_result_export_jobs(SearchJobIdentifier=stoppable_job_id)
    assert any(
        e["ExportJobIdentifier"] == control["ExportJobIdentifier"]
        for e in exports_after["ExportJobs"]
    ), f"expected {control['ExportJobIdentifier']} in {exports_after['ExportJobs']!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _client_error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup():
        # The accepted export job may still be writing: empty and retry BucketNotEmpty to a deadline.
        deadline = time.monotonic() + 30.0
        while True:
            try:
                objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
                if objs:
                    failed = s3.delete_objects(
                        Bucket=bucket,
                        Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                    ).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
                s3.delete_bucket(Bucket=bucket)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchBucket":
                    return
                if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)


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


