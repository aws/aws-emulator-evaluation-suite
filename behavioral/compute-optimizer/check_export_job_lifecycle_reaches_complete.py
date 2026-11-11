"""export-job-lifecycle-reaches-complete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-job-lifecycle-reaches-complete"
GROUP = "state-machine"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """ExportAutoScalingGroupRecommendations to a bucket with the Compute Optimizer policy returns that
    bucket as s3Destination and its job reaches Complete."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    _drain_inflight_jobs(co, "AutoScalingGroup", timeout_s=60.0, interval_s=10.0)
    bucket = _create_export_bucket(ctx)

    job_id, dest_bucket = _export_with_retry(co, bucket, timeout_s=90.0)
    assert dest_bucket == bucket, f"expected s3Destination.bucket={bucket!r}, got {dest_bucket!r}"

    final_status = _poll_export_job(co, job_id, timeout_s=1100.0, interval_s=15.0)
    assert final_status == "Complete", f"expected terminal status Complete, got {final_status!r}"


def _drain_inflight_jobs(co, resource_type: str, timeout_s: float, interval_s: float) -> None:
    """Wait out any pre-existing Queued/InProgress export job of resource_type so this
    check starts from a clean concurrency slate.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = co.describe_recommendation_export_jobs()
        inflight = [
            j
            for j in resp.get("recommendationExportJobs", [])
            if j.get("resourceType") == resource_type and j.get("status") in ("Queued", "InProgress")
        ]
        if not inflight:
            return
        time.sleep(interval_s)


def _export_with_retry(co, bucket: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = co.export_auto_scaling_group_recommendations(
                s3DestinationConfig={"bucket": bucket}
            )
            return resp["jobId"], resp["s3Destination"]["bucket"]
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code not in ("InvalidParameterValueException", "LimitExceededException"):
                raise
            # InvalidParameterValueException: bucket policy hasn't propagated yet.
            # LimitExceededException: another in-flight export job for this resource
            # type is still holding the slot -- wait for it to drain.
            time.sleep(5.0)
    raise AssertionError(f"export never accepted the bucket policy, last error={last_code}")


def _poll_export_job(co, job_id: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = co.describe_recommendation_export_jobs(jobIds=[job_id])
        jobs = resp.get("recommendationExportJobs", [])
        if jobs:
            last = jobs[0]["status"]
            if last in ("Complete", "Failed"):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"export job {job_id} never reached a terminal status, last={last}")


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    bucket = ctx.unique_name("sim2real-co-export-").lower().replace("_", "-")

    if region == "us-east-1":
        # us-east-1 is the S3 CreateBucket API's default region and rejects an explicit
        # LocationConstraint of "us-east-1" -- this branches on ctx.region, not a pin.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "export-job-lifecycle-reaches-complete"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

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
    status = co.get_enrollment_status().get("status")
    if status != "Active":
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
