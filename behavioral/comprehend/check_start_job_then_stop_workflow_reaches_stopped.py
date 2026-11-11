"""start-job-then-stop-workflow-reaches-stopped."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "start-job-then-stop-workflow-reaches-stopped"
GROUP = "e2e-workflow"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopSentimentDetectionJob on a running job returns STOP_REQUESTED and the job reaches STOPPED; a
    second stop fails with InvalidRequestException and its exact message and leaves the job STOPPED."""
    comprehend = ctx.client("comprehend")
    infra = _create_job_infra(ctx, "This is a small sample document for sentiment analysis.\n")

    def _start():
        return comprehend.start_sentiment_detection_job(
            InputDataConfig={"S3Uri": infra["input_s3_uri"], "InputFormat": "ONE_DOC_PER_LINE"},
            OutputDataConfig={"S3Uri": infra["output_s3_uri"]},
            DataAccessRoleArn=infra["role_arn"],
            LanguageCode="en",
        )

    start_resp = _retry_start_job(_start)
    job_id = start_resp["JobId"]

    # Positive control: stopping a currently-running job returns STOP_REQUESTED.
    stop_resp = comprehend.stop_sentiment_detection_job(JobId=job_id)
    assert stop_resp["JobStatus"] == "STOP_REQUESTED", stop_resp

    def _describe():
        return comprehend.describe_sentiment_detection_job(JobId=job_id)["SentimentDetectionJobProperties"]

    props = _poll_until_terminal(_describe, timeout_s=900, interval_s=10)
    assert props["JobStatus"] == "STOPPED", props

    # Break the one thing: stop an already-terminal job.
    code, message = _error(lambda: comprehend.stop_sentiment_detection_job(JobId=job_id))
    assert code == "InvalidRequestException", code
    expected = "Job is already in terminal state."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the job's status was not disturbed by the rejected call.
    after = _describe()
    assert after["JobStatus"] == "STOPPED", after


import json  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

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
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "yes"}]})
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=doc_text.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "yes"}],
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


def _poll_until_terminal(describe_fn, timeout_s: float, interval_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    props: dict[str, Any] = describe_fn()
    while props["JobStatus"] not in ("COMPLETED", "FAILED", "STOPPED"):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"job did not reach a terminal state within {timeout_s}s; last status={props['JobStatus']!r}"
            )
        time.sleep(interval_s)
        props = describe_fn()
    return props


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
