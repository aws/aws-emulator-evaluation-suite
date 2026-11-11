"""stop-dominant-language-detection-job-not-found-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-dominant-language-detection-job-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopDominantLanguageDetectionJob and DescribeDominantLanguageDetectionJob both raise
    JobNotFoundException for a well-formed but nonexistent JobId, while the identical operations
    against a real, freshly-started job (the positive control) succeed."""
    comprehend = ctx.client("comprehend")
    bucket, role_arn = _setup_bucket_and_role(ctx)
    ctx.client("s3").put_object(
        Bucket=bucket,
        Key="input/doc.txt",
        Body=b"This is a small sample document for language detection.\n",
    )

    def _start():
        return comprehend.start_dominant_language_detection_job(
            InputDataConfig={"S3Uri": f"s3://{bucket}/input/doc.txt", "InputFormat": "ONE_DOC_PER_LINE"},
            OutputDataConfig={"S3Uri": f"s3://{bucket}/output/"},
            DataAccessRoleArn=role_arn,
        )

    real_job_id = _retry_role_propagation(_start)["JobId"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, real_job_id))

    # Positive control: describing the real, freshly-started job succeeds.
    real_props = comprehend.describe_dominant_language_detection_job(JobId=real_job_id)[
        "DominantLanguageDetectionJobProperties"
    ]
    assert real_props["JobId"] == real_job_id, real_props

    # Positive control: stopping the real, still-running job succeeds.
    stop_resp = comprehend.stop_dominant_language_detection_job(JobId=real_job_id)
    assert stop_resp["JobId"] == real_job_id, stop_resp

    # Break the one thing: a well-formed but nonexistent JobId.
    fake_job_id = "0" * 32

    for label, call in (
        ("Stop", lambda: comprehend.stop_dominant_language_detection_job(JobId=fake_job_id)),
        ("Describe", lambda: comprehend.describe_dominant_language_detection_job(JobId=fake_job_id)),
    ):
        code, message = _refusal(call, label)
        assert code == "JobNotFoundException", f"unexpected error code from {label}: {code!r}"
        assert message == "Could not find specified job.", (
            f"unexpected error message from {label}: {message!r}"
        )

    # Independent read: a sibling read-only operation on the same job family still works
    # (an emulator that unconditionally rejects every call to this job family would fail here).
    resp = comprehend.list_dominant_language_detection_jobs()
    assert isinstance(resp["DominantLanguageDetectionJobPropertiesList"], list)


# ===== helpers =====
def _refusal(fn, label: str) -> tuple[str, str]:
    """(code, message) of the expected refusal; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected {label} on a nonexistent JobId to be rejected, but it SUCCEEDED: {result!r}")


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 6.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"job start never succeeded within {timeout_s}s (last error: {last_exc!r})")


def _best_effort_stop(ctx, job_id: str) -> None:
    """Stop the job; one that is gone or already finished needs no stop, anything else raises."""
    client = ctx.client("comprehend")
    try:
        client.stop_dominant_language_detection_job(JobId=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "JobNotFoundException":
            return
        if code != "InvalidRequestException":
            raise
        # Stopping a COMPLETED or FAILED job is refused with InvalidRequestException.
        status = client.describe_dominant_language_detection_job(JobId=job_id)["DominantLanguageDetectionJobProperties"]["JobStatus"]
        if status not in ("COMPLETED", "FAILED", "STOPPED", "STOP_REQUESTED"):
            raise


def _setup_bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-comprehend-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "comprehend.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    policy_name = "sim2real-comprehend-s3-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return bucket, role_arn


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
