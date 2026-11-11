"""start-dominant-language-job-duplicate-client-token-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-dominant-language-job-duplicate-client-token-conflict"
GROUP = "concurrency"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent StartDominantLanguageDetectionJob calls reusing one ClientRequestToken with
    different InputDataConfig both succeed as two jobs with distinct JobIds, each keeping the
    InputDataConfig of the request that created it."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="input/doc-a.txt", Body=b"Bob lives in Seattle, Washington.\n")
    s3.put_object(Bucket=bucket, Key="input/doc-b.txt", Body=b"Jane lives in Boston, Massachusetts.\n")
    role_arn = _create_job_role(ctx, bucket)
    comprehend = ctx.client("comprehend")
    token = ctx.unique_name("sim2real-token-")

    def _attempt(input_key, output_suffix):
        return comprehend.start_dominant_language_detection_job(
            ClientRequestToken=token,
            DataAccessRoleArn=role_arn,
            InputDataConfig={"S3Uri": f"s3://{bucket}/{input_key}", "InputFormat": "ONE_DOC_PER_LINE"},
            OutputDataConfig={"S3Uri": f"s3://{bucket}/output-{output_suffix}/"},
        )

    def _call_a():
        return _start_job_with_retry(lambda: _attempt("input/doc-a.txt", "a"))

    def _call_b():
        return _start_job_with_retry(lambda: _attempt("input/doc-b.txt", "b"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_call_a)
        fut_b = pool.submit(_call_b)
        resp_a = fut_a.result()
        resp_b = fut_b.result()

    job_id_a, job_id_b = resp_a["JobId"], resp_b["JobId"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, job_id_a))
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, job_id_b))
    assert job_id_a != job_id_b, (job_id_a, job_id_b)

    described_a = comprehend.describe_dominant_language_detection_job(JobId=job_id_a)[
        "DominantLanguageDetectionJobProperties"
    ]
    described_b = comprehend.describe_dominant_language_detection_job(JobId=job_id_b)[
        "DominantLanguageDetectionJobProperties"
    ]
    assert described_a["InputDataConfig"]["S3Uri"] == f"s3://{bucket}/input/doc-a.txt", described_a
    assert described_b["InputDataConfig"]["S3Uri"] == f"s3://{bucket}/input/doc-b.txt", described_b


# ===== helpers =====
def _best_effort_stop(ctx, job_id):
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


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-comprehend-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's own no-LocationConstraint special case, not a resource pin.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
