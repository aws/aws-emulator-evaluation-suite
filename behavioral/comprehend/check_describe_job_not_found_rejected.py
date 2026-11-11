"""describe-job-not-found-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-job-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeKeyPhrasesDetectionJob returns JobNotFoundException for a
    well-formed but nonexistent JobId, while the identical operation for a real,
    freshly-started job (the positive control) succeeds."""
    comprehend = ctx.client("comprehend")
    infra = _create_job_infra(ctx, "This is a small sample document for key phrase analysis.\n")

    def _start():
        return comprehend.start_key_phrases_detection_job(
            InputDataConfig={"S3Uri": infra["input_s3_uri"], "InputFormat": "ONE_DOC_PER_LINE"},
            OutputDataConfig={"S3Uri": infra["output_s3_uri"]},
            DataAccessRoleArn=infra["role_arn"],
            LanguageCode="en",
        )

    real_job = _retry_start_job(_start)
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, real_job["JobId"]))

    # Positive control: describing the real job succeeds.
    real_props = comprehend.describe_key_phrases_detection_job(JobId=real_job["JobId"])[
        "KeyPhrasesDetectionJobProperties"
    ]
    assert real_props["JobId"] == real_job["JobId"], (
        f"expected DescribeKeyPhrasesDetectionJob to echo JobId {real_job['JobId']!r}, "
        f"got {real_props['JobId']!r}"
    )

    # Break the one thing: describe a well-formed but nonexistent JobId.
    bogus_job_id = uuid.uuid4().hex[:32]
    code, message = _error(lambda: comprehend.describe_key_phrases_detection_job(JobId=bogus_job_id))
    assert code == "JobNotFoundException", f"expected JobNotFoundException, got {code}"
    expected = "Could not find specified job."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====
import json  # noqa: E402

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "comprehend.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _s3_policy(bucket: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutObject"],
                    "Resource": f"arn:aws:s3:::{bucket}/output/*",
                },
            ],
        }
    )


def _create_job_infra(ctx, doc_text: str) -> dict[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-comprehend").replace("_", "-").lower()
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=doc_text.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=_s3_policy(bucket))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))

    return {
        "bucket": bucket,
        "role_arn": role_arn,
        "input_s3_uri": f"s3://{bucket}/input/doc.txt",
        "output_s3_uri": f"s3://{bucket}/output/",
    }


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _retry_start_job(start_fn, timeout_s: float = 90, interval_s: float = 5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return start_fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _best_effort_stop(ctx, job_id: str) -> None:
    """Stop the job; one that is gone or already finished needs no stop, anything else raises."""
    client = ctx.client("comprehend")
    try:
        client.stop_key_phrases_detection_job(JobId=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "JobNotFoundException":
            return
        if code != "InvalidRequestException":
            raise
        # Stopping a COMPLETED or FAILED job is refused with InvalidRequestException.
        status = client.describe_key_phrases_detection_job(JobId=job_id)["KeyPhrasesDetectionJobProperties"]["JobStatus"]
        if status not in ("COMPLETED", "FAILED", "STOPPED", "STOP_REQUESTED"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
