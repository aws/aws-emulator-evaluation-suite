"""stop-terminated-model-customization-job-is-an-idempotent-no-op."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stop-terminated-model-customization-job-is-an-idempotent-no-op"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopModelCustomizationJob on an already-Stopped job is an idempotent no-op: it returns 200
    rather than a conflict error, and the job stays Stopped with the same endTime."""
    bedrock = ctx.client("bedrock")
    bucket = _create_bucket(ctx)
    role_arn = _create_bedrock_role(ctx, bucket)
    train_uri = _upload_training_data(ctx, bucket)
    # Looked up, not pinned: which model is enabled for FINE_TUNING varies by account and region.
    base_model_arn = _first_fine_tunable_model_arn(bedrock)

    def _create_job(job_name: str, model_name: str) -> str:
        resp = _retry_transient(
            lambda: bedrock.create_model_customization_job(
                jobName=job_name,
                customModelName=model_name,
                roleArn=role_arn,
                baseModelIdentifier=base_model_arn,
                trainingDataConfig={"s3Uri": train_uri},
                outputDataConfig={"s3Uri": f"s3://{bucket}/output/"},
                hyperParameters={"epochCount": "1", "batchSize": "1", "learningRate": "0.0005"},
                jobTags=[{"key": "sim2real-check", "value": CHECK}],
                customModelTags=[{"key": "sim2real-check", "value": CHECK}],
            )
        )
        return resp["jobArn"]

    job_arn = _create_job(
        ctx.unique_name("sim2real-bedrock-ftjob-"), ctx.unique_name("sim2real-bedrock-ftmodel-")
    )
    ctx.on_cleanup(lambda: _safe_stop_customization(bedrock, job_arn))

    # positive control: stopping a genuinely running job succeeds and drives it to Stopped; this
    # reaches a terminal state without hours of billed training
    bedrock.stop_model_customization_job(jobIdentifier=job_arn)
    status = _wait_for_status(bedrock, job_arn, {"Stopped", "Failed", "Completed"}, timeout_s=900)
    if status != "Stopped":
        raise AssertionError(
            f"customization job reached terminal status {status!r} instead of "
            "Stopped before we could exercise the double-stop"
        )
    before = bedrock.get_model_customization_job(jobIdentifier=job_arn)

    # StopModelCustomizationJob on the now-Stopped job succeeds as a no-op -- an
    # unexpected error here is the real defect this check exists to catch.
    bedrock.stop_model_customization_job(jobIdentifier=job_arn)

    # effect absent: the no-op does not restart the job or change its terminal state
    after = bedrock.get_model_customization_job(jobIdentifier=job_arn)
    assert after["status"] == "Stopped", f"double-stop must not change status, got {after['status']!r}"
    assert after.get("endTime") == before.get("endTime"), "double-stop must not reset endTime"

    # second control in the same file: stopping a fresh, still-running job also succeeds,
    # and the transition is observed through an independent read at the destination
    control_arn = _create_job(
        ctx.unique_name("sim2real-bedrock-ftjob-ctl-"), ctx.unique_name("sim2real-bedrock-ftmodel-ctl-")
    )
    ctx.on_cleanup(lambda: _safe_stop_customization(bedrock, control_arn))
    bedrock.stop_model_customization_job(jobIdentifier=control_arn)
    control_status = _wait_for_status(bedrock, control_arn, {"Stopped", "Failed", "Completed"}, timeout_s=900)
    assert control_status == "Stopped", f"control job ended in {control_status!r}, expected Stopped"


def _safe_stop_customization(bedrock, job_arn: str) -> None:
    """Stop the job unless it is gone or already terminal; any other failure raises."""
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


def _wait_for_status(bedrock, job_arn: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = ""
    while time.monotonic() < deadline:
        status = bedrock.get_model_customization_job(jobIdentifier=job_arn)["status"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"customization job never reached a terminal status, last={status}")


def _retry_transient(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """A role that was just created may not be assumable by bedrock.amazonaws.com yet."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"still failing after {timeout_s}s: {last_err}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-ftjob-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(lambda: _safe_call(_cleanup))
    return bucket


def _create_bedrock_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-ftjob-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = f"{role_name}-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
    return role_arn


def _upload_training_data(ctx, bucket: str, key: str = "train/data.jsonl") -> str:
    s3 = ctx.client("s3")
    lines = [
        json.dumps({"prompt": f"Say the number {i}.", "completion": str(i)}) for i in range(32)
    ]
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(lines).encode())
    return f"s3://{bucket}/{key}"


def _safe_call(fn) -> None:
    """Run one teardown call: an already-deleted bucket or IAM entity is fine, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchEntity"):
            raise


def _first_fine_tunable_model_arn(bedrock) -> str:
    resp = bedrock.list_foundation_models(byCustomizationType="FINE_TUNING")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
        and "TEXT" in m.get("outputModalities", [])
    ]
    if not summaries:
        raise AssertionError(
            "no ACTIVE text-output foundation model in this account/region supports "
            "FINE_TUNING customization"
        )
    return summaries[0]["modelArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
