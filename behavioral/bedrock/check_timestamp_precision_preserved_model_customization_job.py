"""timestamp-precision-preserved-model-customization-job."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "timestamp-precision-preserved-model-customization-job"
GROUP = "server-side"
SERVICES = ["bedrock"]

# A fine-tuning job is billable compute, so cleanup stops it at once. The base model is
# discovered, not pinned: Bedrock retires foundation models and CreateModelCustomizationJob
# rejects a retired one.
_PREFERRED_MODEL_PREFIX = "amazon.titan-text"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The creationTime reported by GetModelCustomizationJob is stable and
    precise (not re-derived / re-rounded) across repeated reads of the same
    job."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bedrock = ctx.client("bedrock")

    bucket = _create_bucket(ctx, s3)
    train_key = "train.jsonl"
    _put_titan_training_data(s3, bucket, train_key, record_count=32)

    role_arn = _create_customization_role(ctx, iam, bucket)

    job_name = ctx.unique_name("sim2real-bedrock-ftjob-")
    custom_model_name = ctx.unique_name("sim2real-bedrock-ftmodel-")

    base_model_arn = _pick_active_fine_tunable_model_arn(bedrock)

    def _create_job() -> dict[str, Any]:
        return bedrock.create_model_customization_job(
            jobName=job_name,
            customModelName=custom_model_name,
            roleArn=role_arn,
            baseModelIdentifier=base_model_arn,
            trainingDataConfig={"s3Uri": f"s3://{bucket}/{train_key}"},
            outputDataConfig={"s3Uri": f"s3://{bucket}/output/"},
            # Minimal Titan-text hyperparameters (1 epoch, micro batch, the
            # documented default learning rate) -- cheapest job that still runs.
            hyperParameters={
                "epochCount": "1",
                "batchSize": "1",
                "learningRate": "0.00001",
            },
            jobTags=[{"key": "sim2real", "value": CHECK}],
        )

    # The IAM role just got created; Bedrock validates it can be assumed, which
    # can lag IAM's eventual consistency by a few seconds. Retry the actual
    # create call (not a bare sleep) until the role is usable.
    before_create = datetime.now(timezone.utc)
    created = _retry_until_ready(_create_job, timeout_s=90.0, interval_s=5.0)
    after_create = datetime.now(timezone.utc)
    job_arn = created["jobArn"]

    def _cleanup_job() -> None:
        from botocore.exceptions import ClientError

        try:
            bedrock.stop_model_customization_job(jobIdentifier=job_arn)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException":
                raise
            status = bedrock.get_model_customization_job(jobIdentifier=job_arn)["status"]
            if status not in ("Stopping", "Stopped", "Completed", "Failed"):
                raise

    ctx.on_cleanup(_cleanup_job)

    first = bedrock.get_model_customization_job(jobIdentifier=job_arn)
    second = bedrock.get_model_customization_job(jobIdentifier=job_arn)

    assert first["creationTime"] == second["creationTime"], (
        first["creationTime"],
        second["creationTime"],
    )
    # Real precision, not a re-derived/re-rounded epoch: creationTime must fall
    # inside the wall-clock window that bracketed the CreateModelCustomizationJob
    # call, within a tolerance far tighter than a minute. A target that floors
    # the timestamp to a coarse epoch (e.g. the nearest minute) drifts outside
    # this window whenever the real creation second is not itself near :00.
    tolerance = timedelta(seconds=5)
    assert before_create - tolerance <= first["creationTime"] <= after_create + tolerance, (
        "creationTime not within the wall-clock window that bracketed job creation",
        before_create,
        first["creationTime"],
        after_create,
    )


def _pick_active_fine_tunable_model_arn(bedrock: Any) -> str:
    models = bedrock.list_foundation_models(byCustomizationType="FINE_TUNING").get(
        "modelSummaries", []
    )
    active_text = [
        m
        for m in models
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
        and "TEXT" in m.get("outputModalities", [])
    ]
    assert active_text, "no ACTIVE fine-tunable text foundation model available in this account/region"
    preferred = [m for m in active_text if m["modelId"].startswith(_PREFERRED_MODEL_PREFIX)]
    return (preferred or active_text)[0]["modelArn"]


def _create_bucket(ctx, s3: Any) -> str:
    bucket = ctx.unique_name("sim2real-bedrock-ft-").lower().replace("_", "-")
    # S3's CreateBucket rejects a LocationConstraint equal to the default
    # region (us-east-1 itself), so that region is the one legitimate literal
    # here -- not a pin to a particular deployment region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": "true"}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_titan_training_data(s3: Any, bucket: str, key: str, record_count: int) -> None:
    lines = []
    for i in range(record_count):
        lines.append(
            json.dumps(
                {
                    "prompt": f"Classify the sentiment of review #{i}: 'It works great.'",
                    "completion": "positive",
                }
            )
        )
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(lines).encode("utf-8"))


def _create_customization_role(ctx, iam: Any, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-bedrock-ft-role-")
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
        Tags=[{"Key": "sim2real-behav", "Value": "true"}],
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


def _retry_until_ready(fn, timeout_s: float, interval_s: float) -> dict[str, Any]:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever attempting the call"
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
