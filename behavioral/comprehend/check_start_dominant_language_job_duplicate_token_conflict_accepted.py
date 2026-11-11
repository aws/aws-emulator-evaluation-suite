"""start-dominant-language-job-duplicate-token-conflict-accepted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-dominant-language-job-duplicate-token-conflict-accepted"
GROUP = "state-machine"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientRequestToken on StartDominantLanguageDetectionJob with a different
    OutputDataConfig is not rejected: both calls are admitted with distinct JobIds and the first
    job's configuration is unaffected."""
    bucket, role_arn = _setup_bucket_and_role(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="input/doc1.txt", Body=b"A short English document for the token test.")

    _wait_until_role_assumable(ctx, role_arn, timeout_s=90)

    comprehend = ctx.client("comprehend")
    token = ctx.unique_name("sim2real-token-").replace("_", "-")[:64]

    def _start(output_suffix: str):
        return comprehend.start_dominant_language_detection_job(
            ClientRequestToken=token,
            InputDataConfig={"S3Uri": f"s3://{bucket}/input/", "InputFormat": "ONE_DOC_PER_FILE"},
            OutputDataConfig={"S3Uri": f"s3://{bucket}/output/{output_suffix}/"},
            DataAccessRoleArn=role_arn,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    first = _retry_start(lambda: _start("a"))
    ctx.on_cleanup(lambda: _try_stop(ctx, first["JobId"]))
    first_output = _describe(comprehend, first["JobId"])["OutputDataConfig"]["S3Uri"]
    assert first_output.startswith(f"s3://{bucket}/output/a/"), first_output

    # Reuse the same token with a different OutputDataConfig: real AWS accepts this and starts a
    # second, independent job rather than raising ResourceInUseException.
    second = _retry_start(lambda: _start("b"))
    ctx.on_cleanup(lambda: _try_stop(ctx, second["JobId"]))
    assert second["JobId"] != first["JobId"], "expected a distinct second job, not a dedup hit"

    second_output = _describe(comprehend, second["JobId"])["OutputDataConfig"]["S3Uri"]
    assert second_output.startswith(f"s3://{bucket}/output/b/"), second_output

    # Effect isolation: the first job's own configuration was not mutated by the second,
    # reused-token request.
    after_first_output = _describe(comprehend, first["JobId"])["OutputDataConfig"]["S3Uri"]
    assert after_first_output == first_output, (after_first_output, first_output)


# ===== helpers =====


def _describe(comprehend, job_id: str) -> dict:
    return comprehend.describe_dominant_language_detection_job(JobId=job_id)[
        "DominantLanguageDetectionJobProperties"
    ]


def _retry_start(start_fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return start_fn()
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


def _try_stop(ctx, job_id: str) -> None:
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


def _wait_until_role_assumable(ctx, role_arn: str, timeout_s: float) -> None:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-propagation-probe")
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"role never became assumable within {timeout_s}s (last error: {last_exc!r})")


def _setup_bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-comprehend-").lower()
    if ctx.region == "us-east-1":
        # CreateBucket rejects LocationConstraint for the region-less us-east-1 partition default.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    # The AWS principal is limited to the caller's own account; it is only there so the
    # _wait_until_role_assumable probe can assume the role.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "comprehend.amazonaws.com", "AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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
