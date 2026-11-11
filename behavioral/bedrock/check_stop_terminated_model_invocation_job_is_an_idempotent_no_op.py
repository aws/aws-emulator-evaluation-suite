"""stop-terminated-model-invocation-job-is-an-idempotent-no-op."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-terminated-model-invocation-job-is-an-idempotent-no-op"
GROUP = "state-machine"
SERVICES = ["bedrock"]

_RECORD_COUNT = 100  # real AWS batch inference requires a minimum record count


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopModelInvocationJob on an already-Stopped batch job returns 200 and leaves it Stopped.

    A control job that is still running does transition to Stopping/Stopped.
    """
    bedrock = ctx.client("bedrock")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx, s3)
    model_arn, schema = _batch_capable_model(bedrock)
    input_key = "batch-input.jsonl"
    _put_batch_input(s3, bucket, input_key, schema)
    role_arn = _create_batch_role(ctx, iam, bucket)

    def _create_job(job_name: str) -> str:
        resp = _retry_role_propagation(
            lambda: bedrock.create_model_invocation_job(
                jobName=job_name,
                roleArn=role_arn,
                modelId=model_arn,
                inputDataConfig={"s3InputDataConfig": {"s3Uri": f"s3://{bucket}/{input_key}"}},
                outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/output/"}},
                tags=[{"key": "sim2real", "value": CHECK}],
            )
        )
        return resp["jobArn"]

    job_arn = _create_job(ctx.unique_name("sim2real-bedrock-batch-"))
    ctx.on_cleanup(lambda: _safe_stop_invocation(bedrock, job_arn))

    # Stop right away: batch inference has minimum-record and billing costs to run to completion.
    bedrock.stop_model_invocation_job(jobIdentifier=job_arn)
    status = _wait_for_status(
        bedrock, job_arn, {"Stopped", "Failed", "Completed", "PartiallyCompleted"}, timeout_s=600
    )
    if status != "Stopped":
        raise AssertionError(
            f"batch inference job reached terminal status {status!r} instead "
            "of Stopped before we could exercise the double-stop"
        )

    # Two repeats, so one tolerated duplicate racing the first Stop cannot pass by luck.
    for attempt in (2, 3):
        resp = bedrock.stop_model_invocation_job(jobIdentifier=job_arn)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
            f"stop attempt {attempt} on the terminated job returned an unexpected response: {resp!r}"
        )
        unchanged = bedrock.get_model_invocation_job(jobIdentifier=job_arn)["status"]
        assert unchanged == "Stopped", (
            f"expected status to remain 'Stopped' after idempotent stop attempt {attempt}, got {unchanged!r}"
        )

    # Control: Stop on a running job does change its state, so the no-op is terminal-state only.
    control_arn = _create_job(ctx.unique_name("sim2real-bedrock-batch-ctl-"))
    ctx.on_cleanup(lambda: _safe_stop_invocation(bedrock, control_arn))
    bedrock.stop_model_invocation_job(jobIdentifier=control_arn)
    control_status = _poll_until(
        lambda: bedrock.get_model_invocation_job(jobIdentifier=control_arn)["status"],
        lambda s: s in ("Stopping", "Stopped"),
        timeout_s=120.0,
    )
    assert control_status in ("Stopping", "Stopped"), (
        f"expected the control job's stop to take effect, got {control_status!r}"
    )




def _create_bucket(ctx, s3: Any) -> str:
    bucket = ctx.unique_name("sim2real-bedrock-stj-").lower().replace("_", "-")
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
    role_name = ctx.unique_name("sim2real-bedrock-stj-role-")
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
    """(modelArn, input schema) of the first ACTIVE known batch-capable model, Llama 3 first."""
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    active = {
        m.get("modelId"): m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    }
    # ListFoundationModels does not expose batch-inference eligibility, so use a fixed list.
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


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    """Retry only the transient rejection a new IAM role gives while its trust policy propagates."""
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


def _safe_stop_invocation(bedrock, job_arn: str) -> None:
    """Stop the job unless it is gone or already terminal; any other failure raises."""
    try:
        bedrock.stop_model_invocation_job(jobIdentifier=job_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if code != "ValidationException":
            raise
        status = bedrock.get_model_invocation_job(jobIdentifier=job_arn)["status"]
        if status not in ("Stopping", "Stopped", "Completed", "PartiallyCompleted", "Failed", "Expired"):
            raise


def _wait_for_status(bedrock, job_arn: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = ""
    while time.monotonic() < deadline:
        status = bedrock.get_model_invocation_job(jobIdentifier=job_arn)["status"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"batch inference job never reached a terminal status, last={status!r}")


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
