"""export-to-nonexistent-bucket-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-to-nonexistent-bucket-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """ExportEBSVolumeRecommendations to a nonexistent bucket fails with InvalidParameterValueException and
    its exact message and lists no job for it, while an export to a policied bucket creates a job that
    DescribeRecommendationExportJobs returns with that bucket."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    missing_bucket = ctx.unique_name("sim2real-co-missing-").lower().replace("_", "-")

    code, message = _error(
        lambda: co.export_ebs_volume_recommendations(s3DestinationConfig={"bucket": missing_bucket})
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    expected = "The Amazon S3 destination provided does not exist. Confirm your S3 destination and try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no export job was created referencing the nonexistent bucket
    jobs = co.describe_recommendation_export_jobs(
        filters=[{"name": "ResourceType", "values": ["EbsVolume"]}]
    ).get("recommendationExportJobs", [])
    assert all(job.get("destination", {}).get("s3", {}).get("bucket") != missing_bucket for job in jobs)

    # positive control: exporting to a correctly-policied bucket succeeds
    real_bucket = _create_export_bucket(ctx)
    resp = _export_with_retry(co, real_bucket, timeout_s=60.0)
    assert resp["s3Destination"]["bucket"] == real_bucket
    assert resp["jobId"]

    # terminal read: an independent DescribeRecommendationExportJobs call (not the
    # mutating ExportEBSVolumeRecommendations response) confirms the job is discoverable
    # at its destination
    job_id = resp["jobId"]
    describe_resp = co.describe_recommendation_export_jobs(jobIds=[job_id])
    described_jobs = describe_resp.get("recommendationExportJobs", [])
    assert len(described_jobs) == 1
    described_job = described_jobs[0]
    assert described_job["jobId"] == job_id
    assert described_job["destination"]["s3"]["bucket"] == real_bucket


def _export_with_retry(co, bucket: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return co.export_ebs_volume_recommendations(s3DestinationConfig={"bucket": bucket})
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code != "InvalidParameterValueException":
                raise
            time.sleep(5.0)
    raise AssertionError(f"export never accepted the bucket policy, last error={last_code}")


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    bucket = ctx.unique_name("sim2real-co-export-").lower().replace("_", "-")

    # us-east-1 is S3's own no-LocationConstraint special case, not an assumption
    # about which region this check runs in.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "export-to-nonexistent-bucket-rejected"}]})

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
