"""start-search-result-export-job-invalid-role-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-search-result-export-job-invalid-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSearchResultExportJob on a terminal search job with a well-formed ARN that names no
    assumable role is rejected with AccessDeniedException, while the same request without RoleArn
    is accepted."""
    bs = ctx.client("backupsearch")
    s3 = ctx.client("s3")

    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    # Export requires the search job to have reached COMPLETED or STOPPED status
    # (FAILED/RUNNING jobs are rejected with a ValidationException naming the
    # allowed statuses). Explicitly stop it so the RoleArn assertion below isn't masked by
    # that state precondition.
    bs.stop_search_job(SearchJobIdentifier=job_id)
    completed = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=job_id),
        lambda r: r["Status"] in ("COMPLETED", "FAILED", "STOPPED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert completed["Status"] == "STOPPED", f"setup did not reach STOPPED: {completed!r}"

    bucket = ctx.unique_name("sim2real-behav-bksearch-export-").lower()
    _create_bucket(ctx, s3, bucket)

    code, message = _client_error(
        lambda: bs.start_search_result_export_job(
            SearchJobIdentifier=job_id,
            ExportSpecification={"s3ExportSpecification": {"DestinationBucket": bucket}},
            RoleArn="arn:aws:s3:::not-an-iam-role-arn-xxxxxxxx",
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got code={code!r}"
    assert message == "Cross-account pass role is not allowed.", f"unexpected message {message!r}"

    # Effect absent: the rejected call created no export job for this search job.
    rejected_effect = bs.list_search_result_export_jobs(SearchJobIdentifier=job_id)
    assert rejected_effect["ExportJobs"] == [], (
        f"expected no export job after AccessDeniedException, got {rejected_effect!r}"
    )

    # Positive control: the same export request without RoleArn is accepted.
    control = bs.start_search_result_export_job(
        SearchJobIdentifier=job_id,
        ExportSpecification={"s3ExportSpecification": {"DestinationBucket": bucket}},
    )
    export_id = control["ExportJobIdentifier"]
    assert export_id

    # Independent read at the destination (GetSearchResultExportJob and
    # ListSearchResultExportJobs are different operations than the one that
    # created the export job): the accepted export job is visible and wired
    # to this search job, unlike the rejected one above.
    readback = bs.get_search_result_export_job(ExportJobIdentifier=export_id)
    assert readback["ExportJobArn"].endswith(f"/{export_id}"), (
        f"expected readback's ExportJobArn to name {export_id!r}, got {readback!r}"
    )
    assert readback["SearchJobArn"].endswith(f"/{job_id}"), (
        f"expected readback to be wired to search job {job_id!r}, got {readback!r}"
    )
    accepted_effect = bs.list_search_result_export_jobs(SearchJobIdentifier=job_id)
    assert any(j["ExportJobIdentifier"] == export_id for j in accepted_effect["ExportJobs"]), (
        f"expected {export_id!r} to be listed for {job_id!r}, got {accepted_effect!r}"
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)


def _best_effort_stop(bs, job_id: str) -> None:
    try:
        bs.stop_search_job(SearchJobIdentifier=job_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

