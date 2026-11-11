"""describe-report-job-missing-parameter-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "describe-report-job-missing-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeReportJob with a whitespace-only ReportJobId is rejected with
    InvalidParameterValueException instead of a silent no-op lookup; a real report job id succeeds.
    """
    backup = ctx.client("backup")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx, s3)
    plan_name = ctx.unique_name("sim2real_behav_reportplan_")
    backup.create_report_plan(
        ReportPlanName=plan_name,
        ReportDeliveryChannel={"S3BucketName": bucket, "Formats": ["JSON"]},
        ReportSetting={"ReportTemplate": "BACKUP_JOB_REPORT"},
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: backup.delete_report_plan(ReportPlanName=plan_name), "ResourceNotFoundException")
    )

    job = backup.start_report_job(ReportPlanName=plan_name)
    report_job_id = job["ReportJobId"]

    # positive control: describing the real report job id succeeds
    real = backup.describe_report_job(ReportJobId=report_job_id)
    assert real["ReportJob"]["ReportJobId"] == report_job_id, (
        f"expected DescribeReportJob to echo {report_job_id!r}, "
        f"got {real['ReportJob'].get('ReportJobId')!r}"
    )

    # negative: a blank (whitespace-only) ReportJobId is not a valid identifier and is
    # rejected server-side. (An outright empty string collapses the URI segment in a way
    # that does not exercise this validation path at all -- boto3/botocore route it
    # differently before it ever reaches the report-job lookup -- so a whitespace value is
    # used instead: it is non-empty on the wire but still not a real identifier.)
    code, message = _error(lambda: backup.describe_report_job(ReportJobId="   "))
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    expected_message = "Invalid report job ID    . The report job ID must be a valid UUID."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====

def _safe(fn: Callable[[], Any], *missing: str) -> None:
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in missing:
            raise


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so
    accepting an invalid input is reported as such and not as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-behav-reports-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    def _cleanup():
        def _do():
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)

        _safe(_do, "NoSuchBucket")

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
