"""start-search-result-export-job-empty-export-specification-rejected."""
from __future__ import annotations

import time

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-search-result-export-job-empty-export-specification-rejected"
GROUP = "overly-permissive"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSearchResultExportJob on a STOPPED search job with an empty ExportSpecification union
    (sent past client-side validation) fails with InternalServerException and creates no export
    job, while a proper s3ExportSpecification is accepted."""
    bs = ctx.client("backupsearch")
    s3 = ctx.client("s3")
    unvalidated_bs = ctx.client("backupsearch", config=Config(parameter_validation=False))

    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
        Tags={"sim2real": CHECK},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    # Export requires the search job to have reached COMPLETED or STOPPED status
    # (FAILED/RUNNING jobs are rejected with a ValidationException naming the
    # allowed statuses). Explicitly stop it to reach a status where export is permitted, so
    # the malformed-input assertion below isn't masked by that state precondition.
    bs.stop_search_job(SearchJobIdentifier=job_id)
    completed = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=job_id),
        lambda r: r["Status"] in ("COMPLETED", "FAILED", "STOPPED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert completed["Status"] == "STOPPED", f"setup did not reach STOPPED: {completed!r}"

    code, message = _client_error(
        lambda: unvalidated_bs.start_search_result_export_job(
            SearchJobIdentifier=job_id, ExportSpecification={}
        )
    )
    assert code == "InternalServerException", f"expected InternalServerException, got code={code!r}"
    assert message == "Internal Server Error. Please try again", f"unexpected message {message!r}"

    # Effect absent: no export job was created by the rejected call.
    exports = bs.list_search_result_export_jobs(SearchJobIdentifier=job_id)
    assert exports["ExportJobs"] == [], f"expected no export job, got {exports['ExportJobs']!r}"

    # Positive control: the same call with a real export specification succeeds.
    bucket = ctx.unique_name("sim2real-behav-bksearch-export-").lower()
    _create_bucket(ctx, s3, bucket)
    control = bs.start_search_result_export_job(
        SearchJobIdentifier=job_id,
        ExportSpecification={"s3ExportSpecification": {"DestinationBucket": bucket}},
    )
    assert control["ExportJobIdentifier"], f"expected export job id, got {control!r}"


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
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 specifically;
    # this branches on ctx.region, not a hardcoded target.
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
