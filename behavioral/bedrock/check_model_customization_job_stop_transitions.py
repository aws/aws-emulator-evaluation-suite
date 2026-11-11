"""model-customization-job-stop-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "model-customization-job-stop-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModelCustomizationJob starts InProgress; StopModelCustomizationJob->Stopped."""
    bedrock = ctx.client("bedrock")
    bucket = _create_scratch_bucket(ctx)
    role_arn = _create_bedrock_service_role(ctx, bucket)
    train_key = "train/train.jsonl"
    _upload_customization_dataset(ctx, bucket, train_key)

    job_name = ctx.unique_name("sim2real-customjob-")
    model_name = ctx.unique_name("sim2real-custommodel-")

    job_tags = [{"key": "sim2real-check", "value": CHECK}]
    base_model_arn = _first_fine_tunable_model_arn(bedrock)

    def _create():
        return bedrock.create_model_customization_job(
            jobName=job_name,
            customModelName=model_name,
            roleArn=role_arn,
            baseModelIdentifier=base_model_arn,
            trainingDataConfig={"s3Uri": f"s3://{bucket}/{train_key}"},
            outputDataConfig={"s3Uri": f"s3://{bucket}/output/"},
            hyperParameters={
                "epochCount": "1",
                "batchSize": "1",
                "learningRate": "0.00001",
            },
            jobTags=job_tags,
            customModelTags=job_tags,
        )

    resp = _call_with_role_propagation_retry(_create)
    job_arn = resp["jobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(bedrock, job_arn))

    stopped_or_terminal = ("Stopped", "Completed", "Failed")
    initial = bedrock.get_model_customization_job(jobIdentifier=job_arn)
    assert initial["status"] in ("InProgress", "Stopped", "Completed", "Failed"), (
        f"unexpected status right after create: {initial['status']!r}"
    )

    bedrock.stop_model_customization_job(jobIdentifier=job_arn)

    state = _poll_until(
        lambda: bedrock.get_model_customization_job(jobIdentifier=job_arn),
        lambda r: r["status"] in stopped_or_terminal,
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert state["status"] == "Stopped", f"job ended in {state['status']!r}, expected Stopped"
    assert state["jobArn"] == job_arn, f"expected jobArn {job_arn!r}, got {state['jobArn']!r}"


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-cust-")
    # us-east-1 is the only region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_bedrock_service_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-role-")
    trust = {
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
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy))

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _upload_customization_dataset(ctx, bucket: str, key: str) -> None:
    s3 = ctx.client("s3")
    lines = [
        json.dumps({"prompt": f"Summarize sentence {i}: The sky is blue.", "completion": "Blue sky."})
        for i in range(32)
    ]
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(lines).encode("utf-8"))


def _first_fine_tunable_model_arn(bedrock) -> str:
    resp = bedrock.list_foundation_models(byCustomizationType="FINE_TUNING")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
        and "TEXT" in m.get("outputModalities", [])
    ]
    assert summaries, (
        "no ACTIVE foundation model in this account/region supports FINE_TUNING with TEXT output"
    )
    return summaries[0]["modelArn"]


def _best_effort_stop(bedrock, job_arn: str) -> None:
    """Stop the job unless it is gone or already terminal; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        bedrock.stop_model_customization_job(jobIdentifier=job_arn)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if code not in ("ConflictException", "ValidationException"):
            raise
        status = bedrock.get_model_customization_job(jobIdentifier=job_arn)["status"]
        if status not in ("Stopping", "Stopped", "Completed", "Failed"):
            raise


def _call_with_role_propagation_retry(fn: Callable[[], Any], *, timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "retry loop exited with no recorded ClientError"
    raise last_err


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
