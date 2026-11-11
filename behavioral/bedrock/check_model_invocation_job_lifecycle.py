"""model-invocation-job-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-invocation-job-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock"]

_RECORD_COUNT = 100  # real AWS batch inference requires a minimum record count


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModelInvocationJob starts a job that reaches InProgress, and
    StopModelInvocationJob on the running job drives it to the terminal Stopped state."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bedrock = ctx.client("bedrock")

    bucket = _create_bucket(ctx, s3)
    model_arn, schema = _batch_capable_model(bedrock)
    input_key = "batch-input.jsonl"
    _put_batch_input(s3, bucket, input_key, schema)
    role_arn = _create_batch_role(ctx, iam, bucket)

    job_name = ctx.unique_name("sim2real-batch-job-")

    def _create_job() -> dict[str, Any]:
        return bedrock.create_model_invocation_job(
            jobName=job_name,
            roleArn=role_arn,
            modelId=model_arn,
            inputDataConfig={"s3InputDataConfig": {"s3Uri": f"s3://{bucket}/{input_key}"}},
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/output/"}},
            tags=[{"key": "sim2real", "value": CHECK}],
        )

    created = _retry_until_ready(_create_job, timeout_s=90.0, interval_s=5.0)
    job_arn = created["jobArn"]
    ctx.on_cleanup(lambda: _try_stop(bedrock, job_arn))

    def _probe():
        return bedrock.get_model_invocation_job(jobIdentifier=job_arn)

    # Wait (bounded) past Submitted/Validating/Scheduled: Stop must hit a RUNNING job. A
    # 100-record job runs for minutes once InProgress, and the short poll interval reads it
    # well inside that window.
    started_running = _poll_until(
        ctx,
        _probe,
        lambda r: r["status"] not in ("Submitted", "Validating", "Scheduled"),
        timeout_s=600.0,
        interval_s=2.0,
    )
    assert started_running["status"] == "InProgress", (
        f"job reached {started_running['status']!r} before Stop, expected InProgress"
    )

    bedrock.stop_model_invocation_job(jobIdentifier=job_arn)

    final = _poll_until(
        ctx,
        _probe,
        lambda r: r["status"] in ("Stopped", "Completed", "PartiallyCompleted", "Failed", "Expired"),
        timeout_s=600.0,
        interval_s=5.0,
    )
    assert final["status"] == "Stopped", f"job ended in {final['status']!r} instead of Stopped"


def _create_bucket(ctx, s3: Any) -> str:
    bucket = ctx.unique_name("sim2real-bedrock-mij-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _batch_input_record(schema: str, i: int) -> dict[str, Any]:
    prompt = f"Say hello in one short sentence. (variant {i})"
    if schema == "llama":
        model_input = {
            "prompt": (
                "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n"
                f"{prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
            ),
            "max_gen_len": 16,
            "temperature": 0,
        }
    else:
        model_input = {
            "inputText": prompt,
            "textGenerationConfig": {"maxTokenCount": 16, "temperature": 0},
        }
    return {"recordId": f"REC{i:05d}", "modelInput": model_input}


def _put_batch_input(s3: Any, bucket: str, key: str, schema: str) -> None:
    lines = [json.dumps(_batch_input_record(schema, i)) for i in range(_RECORD_COUNT)]
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(lines).encode("utf-8"))


def _create_batch_role(ctx, iam: Any, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-bedrock-mij-role-")
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(inline_policy))

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _batch_capable_model(bedrock: Any) -> tuple[str, str]:
    """Return (modelArn, input-schema-name) for the first ACTIVE on-demand text model
    in this account that is known to support batch inference, preferring the Llama 3
    family and falling back to Titan -- whichever this account still offers."""
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    active = {
        m.get("modelId"): m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    }
    # Bedrock does not expose batch-inference eligibility through ListFoundationModels.
    for model_id, schema in (
        ("meta.llama3-1-8b-instruct-v1:0", "llama"),
        ("meta.llama3-1-70b-instruct-v1:0", "llama"),
        ("amazon.titan-text-lite-v1", "titan"),
        ("amazon.titan-text-express-v1", "titan"),
    ):
        if model_id in active:
            return active[model_id]["modelArn"], schema
    raise AssertionError(
        "none of the known batch-inference-capable on-demand text models "
        "(meta.llama3-*-instruct/amazon.titan-text-*) are ACTIVE in this account/region"
    )


def _retry_until_ready(fn, timeout_s: float, interval_s: float) -> dict[str, Any]:
    """Retry only the transient rejection a just-created IAM role produces while its
    trust policy propagates -- never a permanent rejection (an unsupported model, a
    malformed request), which would otherwise burn the whole timeout before failing."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "").lower()
            transient = code == "AccessDeniedException" or (
                code == "ValidationException" and ("role" in message or "trust" in message)
            )
            if not transient:
                raise
            last_exc = exc
            time.sleep(interval_s)
    assert last_exc is not None, "loop exited without ever calling fn()"
    raise last_exc


def _try_stop(bedrock, job_arn) -> None:
    """Stop the job unless it is gone or already terminal; any other failure raises."""
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, timeout_s=60.0, interval_s=2.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"the run budget ended first; not graded (last={last!r})")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
