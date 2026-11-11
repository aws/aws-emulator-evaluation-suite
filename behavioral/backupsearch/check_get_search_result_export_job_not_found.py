"""get-search-result-export-job-not-found."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-search-result-export-job-not-found"
GROUP = "error-semantics"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSearchResultExportJob for an export job identifier that was never created is
    rejected with ResourceNotFoundException, while the identical read against a real
    export job (the in-file positive control) succeeds and returns its ARN."""
    bs = ctx.client("backupsearch")
    s3 = ctx.client("s3")

    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    # Export is gated on the search job reaching COMPLETED/STOPPED; stop it rather than waiting for
    # the search itself to finish.
    bs.stop_search_job(SearchJobIdentifier=job_id)
    stopped = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=job_id),
        lambda r: r["Status"] in ("COMPLETED", "FAILED", "STOPPED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert stopped["Status"] == "STOPPED", f"setup did not reach STOPPED: {stopped!r}"

    bucket = ctx.unique_name("sim2real-behav-bksearch-export-").lower()
    _create_bucket(ctx, s3, bucket)

    real_export = bs.start_search_result_export_job(
        SearchJobIdentifier=job_id,
        ExportSpecification={"s3ExportSpecification": {"DestinationBucket": bucket}},
    )
    real_export_id = real_export["ExportJobIdentifier"]

    bogus_id = str(uuid.uuid4())
    code, message = _client_error(
        lambda: bs.get_search_result_export_job(ExportJobIdentifier=bogus_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for unknown export job id, got code={code!r}"
    )
    assert message == "Resource is not found", f"unexpected message {message!r}"

    # Positive control: the identical read against the real export job succeeds. Note:
    # GetSearchResultExportJobOutput does NOT echo ExportJobIdentifier back,
    # even though the Smithy model marks that member required — only
    # ExportJobArn, which embeds the same id, is actually returned.
    control = bs.get_search_result_export_job(ExportJobIdentifier=real_export_id)
    assert control["ExportJobArn"] == real_export["ExportJobArn"], (
        f"expected control read to return the export job just created "
        f"({real_export['ExportJobArn']!r}), got {control!r}"
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
