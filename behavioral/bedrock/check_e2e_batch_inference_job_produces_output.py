"""e2e-batch-inference-job-produces-output."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-batch-inference-job-produces-output"
GROUP = "state-machine"
SERVICES = ["bedrock"]

# A batch inference job runs real, billable model invocations and can take a long time to schedule
# and run on real AWS. The minimum record count keeps it as small as real AWS allows. Not every
# model that serves on-demand invocations supports batch inference, and it varies by region: real
# AWS rejects CreateModelInvocationJob for amazon.titan-text-lite-v1, amazon.titan-text-express-v1,
# amazon.titan-text-premier-v1:0, amazon.nova-micro-v1:0 and cohere.command-r-v1:0 in us-west-2
# with "Batch inference is not supported for model ... in region us-west-2".
# meta.llama3-1-8b-instruct-v1:0 supports batch inference in the regions this suite targets.
_MODEL_ID = "meta.llama3-1-8b-instruct-v1:0"
_RECORD_COUNT = 100  # real AWS batch inference requires a minimum record count
_JOB_TIMEOUT_S = 3600.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateModelInvocationJob runs a batch inference job to completion and the
    observable consequence -- output actually written to S3, status Completed --
    is asserted, not just intermediate call shapes."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bedrock = ctx.client("bedrock")

    bucket = _create_bucket(ctx, s3)
    input_key = "batch-input.jsonl"
    _put_batch_input(s3, bucket, input_key, _RECORD_COUNT)
    role_arn = _create_batch_role(ctx, iam, bucket)

    job_name = ctx.unique_name("sim2real-bedrock-batchjob-")

    def _create_job() -> dict[str, Any]:
        return bedrock.create_model_invocation_job(
            jobName=job_name,
            roleArn=role_arn,
            modelId=_MODEL_ID,
            inputDataConfig={"s3InputDataConfig": {"s3Uri": f"s3://{bucket}/{input_key}"}},
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/output/"}},
            tags=[{"key": "sim2real:managed", "value": "true"}],
        )

    created = _retry_until_ready(ctx, _create_job, timeout_s=90.0)
    job_arn = created["jobArn"]

    def _cleanup_job() -> None:
        """Stop the job unless it is gone or already terminal; any other failure raises."""
        from botocore.exceptions import ClientError

        try:
            bedrock.stop_model_invocation_job(jobIdentifier=job_arn)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException":
                raise
            status = bedrock.get_model_invocation_job(jobIdentifier=job_arn)["status"]
            if status not in ("Stopping", "Stopped", "Completed", "PartiallyCompleted", "Failed", "Expired"):
                raise

    ctx.on_cleanup(_cleanup_job)

    job = _wait_job_status(
        ctx,
        bedrock,
        job_arn,
        {"Completed", "PartiallyCompleted", "Failed", "Stopped", "Expired"},
        timeout_s=_JOB_TIMEOUT_S,
    )
    assert job["status"] == "Completed", (job["status"], job.get("message"))
    assert job.get("successRecordCount", 0) == _RECORD_COUNT, job

    output_objs = s3.list_objects_v2(Bucket=bucket, Prefix="output/").get("Contents", [])
    output_objs = [o for o in output_objs if o["Size"] > 0]
    assert output_objs, "batch inference job reported Completed but wrote no output objects"


def _create_bucket(ctx, s3: Any) -> str:
    bucket = ctx.unique_name("sim2real-bedrock-batch-").lower().replace("_", "-")
    # us-east-1 is S3's CreateBucket default region: passing a LocationConstraint for it is
    # itself rejected. This branches on the API quirk, not a hardcoded target region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )

    def _cleanup() -> None:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_batch_input(s3: Any, bucket: str, key: str, record_count: int) -> None:
    lines = [
        json.dumps(
            {
                "recordId": f"REC{i:05d}",
                "modelInput": {
                    "prompt": f"Say hello in one short sentence. (variant {i})",
                    "max_gen_len": 16,
                    "temperature": 0,
                },
            }
        )
        for i in range(record_count)
    ]
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(lines).encode("utf-8"))


def _create_batch_role(ctx, iam: Any, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-bedrock-batch-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(inline_policy)
    )

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _retry_until_ready(ctx, fn, timeout_s: float) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(2.0)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever calling fn()"
    if _budget_spent(ctx):
        raise TimeoutError(f"retrying {last_exc}: the run budget ended first; not graded") from last_exc
    raise last_exc


def _wait_job_status(ctx, bedrock: Any, job_arn: str, target_statuses: set[str], timeout_s: float) -> dict[str, Any]:
    """Poll the job every 2 s for timeout_s, bounded by the runner's remaining time less 5 s."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = bedrock.get_model_invocation_job(jobIdentifier=job_arn)
        last_status = resp["status"]
        if last_status in target_statuses:
            return resp
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"job {job_arn} reaching {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(
        f"model invocation (batch inference) job {job_arn} did not reach "
        f"{target_statuses} within {timeout_s:.0f}s, last status {last_status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
