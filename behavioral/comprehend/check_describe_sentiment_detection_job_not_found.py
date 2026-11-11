"""describe-sentiment-detection-job-not-found."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-sentiment-detection-job-not-found"
GROUP = "error-semantics"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSentimentDetectionJob returns JobNotFoundException for a well-formed
    but nonexistent JobId, while the identical operation for a real, freshly-started
    job (the positive control) succeeds."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    input_key = "input/doc.txt"
    s3.put_object(
        Bucket=bucket,
        Key=input_key,
        Body=b"Bob lives in Seattle. He is a software engineer at Amazon.\n",
    )
    role_arn = _create_job_role(ctx, bucket)
    comprehend = ctx.client("comprehend")

    def _start():
        return comprehend.start_sentiment_detection_job(
            LanguageCode="en",
            DataAccessRoleArn=role_arn,
            InputDataConfig={
                "S3Uri": f"s3://{bucket}/{input_key}",
                "InputFormat": "ONE_DOC_PER_LINE",
            },
            OutputDataConfig={"S3Uri": f"s3://{bucket}/output/"},
        )

    real_job = _start_job_with_retry(_start)
    real_job_id = real_job["JobId"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, real_job_id))

    # Positive control: describing the real job succeeds.
    real_props = comprehend.describe_sentiment_detection_job(JobId=real_job_id)[
        "SentimentDetectionJobProperties"
    ]
    assert real_props["JobId"] == real_job_id, real_props

    # Break the one thing: describe a well-formed but nonexistent JobId.
    bogus_job_id = uuid.uuid4().hex[:32]
    code, message = _error(lambda: comprehend.describe_sentiment_detection_job(JobId=bogus_job_id))
    assert code == "JobNotFoundException", f"expected JobNotFoundException, got {code!r}"
    expected = "Could not find specified job."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====
def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-comprehend-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_job_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-comprehend-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "comprehend.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="comprehend-job-access", PolicyDocument=json.dumps(policy_doc))
    return role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="comprehend-job-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _start_job_with_retry(fn, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "").lower()
            if code in ("AccessDeniedException", "InvalidRequestException") and (
                "role" in message or "assume" in message or "permission" in message
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc if last_exc is not None else RuntimeError("job start retry timed out")


def _best_effort_stop(ctx, job_id: str) -> None:
    """Stop the job; one that is gone or already finished needs no stop, anything else raises."""
    from botocore.exceptions import ClientError

    client = ctx.client("comprehend")
    try:
        client.stop_sentiment_detection_job(JobId=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "JobNotFoundException":
            return
        if code != "InvalidRequestException":
            raise
        # Stopping a COMPLETED or FAILED job is refused with InvalidRequestException.
        status = client.describe_sentiment_detection_job(JobId=job_id)["SentimentDetectionJobProperties"]["JobStatus"]
        if status not in ("COMPLETED", "FAILED", "STOPPED", "STOP_REQUESTED"):
            raise


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
