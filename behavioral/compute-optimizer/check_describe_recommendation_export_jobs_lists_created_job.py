"""describe-recommendation-export-jobs-lists-created-job."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-recommendation-export-jobs-lists-created-job"
GROUP = "state-machine"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """DescribeRecommendationExportJobs by jobId returns exactly the job ExportLambdaFunctionRecommendations
    just created, with resourceType LambdaFunction, the requested bucket and a Queued, InProgress or
    Complete status, and the job then reaches Complete."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    bucket = _create_export_bucket(ctx)

    job_id, dest_bucket = _export_with_retry(co, bucket, timeout_s=60.0)
    assert dest_bucket == bucket, f"expected s3Destination.bucket={bucket!r}, got {dest_bucket!r}"

    resp = co.describe_recommendation_export_jobs(jobIds=[job_id])
    jobs = resp.get("recommendationExportJobs", [])
    assert len(jobs) == 1, f"expected exactly 1 job for jobIds=[{job_id}], got {len(jobs)}"
    job = jobs[0]
    assert job["jobId"] == job_id, f"expected jobId={job_id!r}, got {job['jobId']!r}"
    assert job["resourceType"] == "LambdaFunction", (
        f"expected resourceType='LambdaFunction', got {job['resourceType']!r}"
    )
    assert job["destination"]["s3"]["bucket"] == bucket, (
        f"expected destination.s3.bucket={bucket!r}, got {job['destination']['s3']['bucket']!r}"
    )

    # A job accepted against a correctly-policied bucket is Queued or InProgress until the async
    # export runs, and a fast export can already be Complete; it never reads Failed.
    assert job["status"] in ("Queued", "InProgress", "Complete"), (
        f"expected Queued, InProgress or Complete right after acceptance, got {job['status']!r} "
        f"(failureReason={job.get('failureReason')!r})"
    )

    final = _poll_job_terminal(co, job_id, timeout_s=300.0, interval_s=5.0)
    assert final["status"] == "Complete", (
        f"expected the export job to reach Complete, got {final['status']!r} "
        f"(failureReason={final.get('failureReason')!r})"
    )


def _poll_job_terminal(co, job_id: str, timeout_s: float, interval_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        jobs = co.describe_recommendation_export_jobs(jobIds=[job_id])["recommendationExportJobs"]
        last = jobs[0]["status"] if jobs else None
        if last in ("Complete", "Failed"):
            return jobs[0]
        time.sleep(interval_s)
    raise AssertionError(f"export job {job_id} never reached a terminal status, last={last!r}")


def _export_with_retry(co, bucket: str, timeout_s: float):
    """Bounded retry: the bucket policy set moments ago by _create_export_bucket can
    take a few seconds to become visible to Compute Optimizer, which answers
    InvalidParameterValueException in the interim. Retry that specific code only,
    up to timeout_s, instead of an unconditional pre-sleep.
    """
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = co.export_lambda_function_recommendations(s3DestinationConfig={"bucket": bucket})
            return resp["jobId"], resp["s3Destination"]["bucket"]
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code != "InvalidParameterValueException":
                raise
            time.sleep(5.0)
    raise AssertionError(f"export never accepted the bucket policy, last error={last_code}")


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    bucket = ctx.unique_name("sim2real-co-export-").lower().replace("_", "-")

    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for -- an S3
    # API quirk, not a pinned working region; `region` above still comes from ctx.region.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "compute-optimizer-export-jobs-lists-created-job"}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)

    source_arn_prefix = f"arn:aws:compute-optimizer:{region}:{account_id}:*"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "compute-optimizer.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": source_arn_prefix},
                },
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "compute-optimizer.amazonaws.com"},
                "Action": "s3:GetBucketPolicyStatus",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": source_arn_prefix},
                },
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "compute-optimizer.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/compute-optimizer/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account_id,
                    },
                    "ArnLike": {"aws:SourceArn": source_arn_prefix},
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Opt the account in as a precondition, and leave it opted in.

    Enrollment is deliberately not restored: after an opt-out AWS refuses an opt-in for 24
    hours ("Cannot opt-in within 24 hours of opt-out"), so a restore would fail every later
    check in the account for a day.
    """
    status = co.get_enrollment_status()["status"]
    if status == "Active":
        return
    co.update_enrollment_status(status="Active")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = co.get_enrollment_status().get("status")
        if status == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"account never reached Active enrollment status, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
