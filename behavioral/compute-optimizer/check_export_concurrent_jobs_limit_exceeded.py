"""export-concurrent-jobs-limit-exceeded."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-concurrent-jobs-limit-exceeded"
GROUP = "concurrency"
SERVICES = ["compute-optimizer"]

#: Export pairs tried before the check concludes no first job stays in flight long enough.
_PAIR_ATTEMPTS = 3


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """A second ExportEC2InstanceRecommendations while the first job is in flight fails with
    LimitExceededException and its exact message, and no second job is in flight; a pair whose
    first job finished before the second call is retried, never graded."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    _drain_inflight_jobs(co, "Ec2Instance", timeout_s=30.0, interval_s=5.0)
    bucket = _create_export_bucket(ctx)

    # One attempt only: botocore retries LimitExceededException as throttling, and a retry
    # that outlives the first job would turn the refusal into a second accepted job.
    co_once = ctx.client("compute-optimizer", config=Config(retries={"total_max_attempts": 1}))
    refusal = None
    for _ in range(_PAIR_ATTEMPTS):
        first_job_id = _export_with_retry(co, bucket, timeout_s=120.0)
        try:
            second = co_once.export_ec2_instance_recommendations(
                s3DestinationConfig={"bucket": bucket}
            )
        except ClientError as err:
            refusal = (err.response["Error"]["Code"], err.response["Error"]["Message"])
            break
        # Accepted: that is a refusal missed only if the first job had already finished.
        first_status = _job_status(co, first_job_id)
        assert first_status in ("Complete", "Failed"), (
            f"a second export ({second['jobId']}) was accepted while the first job "
            f"{first_job_id} was still {first_status!r}"
        )
        _drain_export_job(co, second["jobId"], timeout_s=130.0, interval_s=5.0)
    assert refusal is not None, (
        f"the first export job finished before the second export call in each of "
        f"{_PAIR_ATTEMPTS} attempts, so no export was ever made while one was in flight"
    )
    code, message = refusal
    assert code == "LimitExceededException", f"expected LimitExceededException, got {code}"
    assert message == "Export job limit exceeded. You can only have one active job per resource type at a time.", f"unexpected LimitExceededException message: {message!r}"

    # The rejected call must have created no second job: an independent read of the
    # in-flight set for this resource type holds at most the first job.
    inflight_ids = [
        j["jobId"]
        for j in co.describe_recommendation_export_jobs().get("recommendationExportJobs", [])
        if j.get("resourceType") == "Ec2Instance" and j.get("status") in ("Queued", "InProgress")
    ]
    assert set(inflight_ids) <= {first_job_id}, (
        f"expected only the first job ({first_job_id}) in flight after the rejection, got {inflight_ids}"
    )

    # Drain the accepted job to a terminal status -- otherwise it keeps holding the
    # account's one-in-flight-per-resource-type slot and starves any other check that
    # also exports EC2 instance recommendations.
    _drain_export_job(co, first_job_id, timeout_s=130.0, interval_s=5.0)


def _job_status(co, job_id: str) -> str | None:
    jobs = co.describe_recommendation_export_jobs(jobIds=[job_id]).get("recommendationExportJobs", [])
    return jobs[0]["status"] if jobs else None


def _drain_inflight_jobs(co, resource_type: str, timeout_s: float, interval_s: float) -> None:
    """Wait out any pre-existing Queued/InProgress export job of resource_type so this
    check starts from a clean concurrency slate (a stuck/slow job from an earlier run
    would otherwise make the account-wide one-in-flight-per-resource-type limit look
    like it's already exhausted before this check even starts).
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


def _export_with_retry(co, bucket: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = co.export_ec2_instance_recommendations(s3DestinationConfig={"bucket": bucket})
            return resp["jobId"]
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code not in ("InvalidParameterValueException", "LimitExceededException"):
                raise
            time.sleep(5.0)
    raise AssertionError(f"export never accepted the bucket policy, last error={last_code}")


def _drain_export_job(co, job_id: str, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = co.describe_recommendation_export_jobs(jobIds=[job_id])
        jobs = resp.get("recommendationExportJobs", [])
        if jobs and jobs[0]["status"] in ("Complete", "Failed"):
            return
        time.sleep(interval_s)

def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    bucket = ctx.unique_name("sim2real-co-export-").lower().replace("_", "-")

    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
