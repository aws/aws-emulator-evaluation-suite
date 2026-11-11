"""model-invocation-job-stop-transitions-to-stopped."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "model-invocation-job-stop-transitions-to-stopped"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopModelInvocationJob on a freshly-started batch inference job transitions its
    status to Stopped as observed through GetModelInvocationJob."""
    bedrock = ctx.client("bedrock")
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    records = "\n".join(
        json.dumps(
            {
                "recordId": f"REC{i:06d}",
                "modelInput": {
                    "inputText": "Say a short hello.",
                    "textGenerationConfig": {"maxTokenCount": 8},
                },
            }
        )
        for i in range(100)
    ).encode()
    s3.put_object(Bucket=bucket, Key="batch/input.jsonl", Body=records)
    role_arn = _create_bedrock_role(ctx, bucket)

    job_name = ctx.unique_name("sim2real-invjob-")

    def _create_with(model_arn):
        return _retry_transient(
            lambda: bedrock.create_model_invocation_job(
                jobName=job_name,
                roleArn=role_arn,
                modelId=model_arn,
                inputDataConfig={
                    "s3InputDataConfig": {"s3Uri": f"s3://{bucket}/batch/input.jsonl"}
                },
                outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/batch-out/"}},
                tags=[
                    {"key": "sim2real:managed", "value": "true"},
                    {"key": "sim2real:check", "value": CHECK},
                ],
            )
        )

    job_arn = _create_job_against_a_batch_capable_model(bedrock, _create_with)
    ctx.on_cleanup(lambda: _best_effort_stop(bedrock, job_arn))

    bedrock.stop_model_invocation_job(jobIdentifier=job_arn)

    def _probe():
        return bedrock.get_model_invocation_job(jobIdentifier=job_arn)

    final = _poll_until(_probe, lambda r: r["status"] == "Stopped", timeout_s=600.0, interval_s=15.0)
    assert final["status"] == "Stopped", (
        f"expected job {job_arn} to transition to Stopped after StopModelInvocationJob, "
        f"got {final['status']!r}"
    )
    assert final["jobArn"] == job_arn, f"expected jobArn {job_arn!r}, got {final['jobArn']!r}"



def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={
            "TagSet": [
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real:check", "Value": CHECK},
            ]
        },
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_bedrock_role(ctx, bucket):
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
    )["Role"]["Arn"]
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
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy)
    )

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_transient(fn, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDeniedException":
                # IAM role trust-policy propagation lag, not a permanent rejection.
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


_BATCH_MODEL_PREFERENCE = (
    "amazon.titan-text-express-v1",
    "amazon.titan-text-lite-v1",
    "amazon.nova-lite-v1:0",
    "amazon.nova-micro-v1:0",
    "meta.llama3-1-8b-instruct-v1:0",
    "mistral.mistral-large-2407-v1:0",
)


def _batch_capable_model_arns(bedrock):
    """ACTIVE on-demand text models, ordered by a fixed preference list.

    The model is discovered from the catalog rather than pinned, since availability varies."""
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    active = {
        m["modelId"]: m["modelArn"]
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    }
    ordered = [active[model_id] for model_id in _BATCH_MODEL_PREFERENCE if model_id in active]
    if not ordered:
        raise AssertionError(
            "none of the preferred batch-capable on-demand text models "
            f"{_BATCH_MODEL_PREFERENCE} are ACTIVE in this account/region; ACTIVE models seen: "
            f"{sorted(active)}"
        )
    return ordered


def _create_job_against_a_batch_capable_model(bedrock, create_with):
    """Try each candidate model in turn, skipping one rejected with ValidationException
    because it does not support batch inference."""
    from botocore.exceptions import ClientError

    last_err = None
    for model_arn in _batch_capable_model_arns(bedrock):
        try:
            return create_with(model_arn)["jobArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationException":
                last_err = e
                continue
            raise
    raise AssertionError(
        f"no preferred candidate model accepted a batch inference job; last error: {last_err}"
    )


def _best_effort_stop(bedrock, job_arn):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
