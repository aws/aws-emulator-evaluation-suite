"""start-job-duplicate-token-mismatched-params-creates-second-job."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-job-duplicate-token-mismatched-params-creates-second-job"
GROUP = "state-machine"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with a different OutputDataConfig creates a second, independent
    key-phrases job with its own JobId and OutputDataConfig, leaving the first job unaffected."""
    comprehend = ctx.client("comprehend")
    infra = _create_job_infra(ctx, "This is a small sample document for key phrase analysis.\n")
    token = ctx.unique_name("sim2real-token-").replace("_", "-")

    def _start(output_suffix: str):
        return comprehend.start_key_phrases_detection_job(
            InputDataConfig={"S3Uri": infra["input_s3_uri"], "InputFormat": "ONE_DOC_PER_LINE"},
            OutputDataConfig={"S3Uri": infra["output_s3_uri"] + output_suffix},
            DataAccessRoleArn=infra["role_arn"],
            LanguageCode="en",
            ClientRequestToken=token,
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )

    # First use of the token succeeds normally.
    first = _retry_start_job(lambda: _start("a/"))
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, first["JobId"]))
    first_output = comprehend.describe_key_phrases_detection_job(JobId=first["JobId"])[
        "KeyPhrasesDetectionJobProperties"
    ]["OutputDataConfig"]["S3Uri"]

    # Reuse the same token with a different OutputDataConfig: the real service accepts this and
    # starts a second, independent job rather than raising ResourceInUseException.
    second = _retry_start_job(lambda: _start("b/"))
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, second["JobId"]))
    assert second["JobId"] != first["JobId"], "expected a distinct second job, not a dedup hit"

    second_output = comprehend.describe_key_phrases_detection_job(JobId=second["JobId"])[
        "KeyPhrasesDetectionJobProperties"
    ]["OutputDataConfig"]["S3Uri"]
    assert second_output.startswith(infra["output_s3_uri"] + "b/"), second_output

    # Effect isolation: the first job's own configuration was not mutated by the second, reused-
    # token request.
    after_output = comprehend.describe_key_phrases_detection_job(JobId=first["JobId"])[
        "KeyPhrasesDetectionJobProperties"
    ]["OutputDataConfig"]["S3Uri"]
    assert after_output == first_output, (after_output, first_output)
    assert after_output.startswith(infra["output_s3_uri"] + "a/"), after_output



# ===== helpers =====
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=doc_text.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "true"}],
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


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


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
