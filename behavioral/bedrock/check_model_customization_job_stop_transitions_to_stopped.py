"""model-customization-job-stop-transitions-to-stopped."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "model-customization-job-stop-transitions-to-stopped"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopModelCustomizationJob on a freshly-started job transitions its status to
    Stopped (via Stopping) as observed through GetModelCustomizationJob."""
    bedrock = ctx.client("bedrock")
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    training_body = "\n".join(
        json.dumps({"prompt": f"sim2real training prompt {i}", "completion": f"answer {i}"})
        for i in range(50)
    ).encode()
    s3.put_object(Bucket=bucket, Key="train/data.jsonl", Body=training_body)
    role_arn = _create_bedrock_role(ctx, bucket)
    base_model_arn = _first_fine_tunable_model_arn(bedrock)

    job_name = ctx.unique_name("sim2real-customjob-")
    custom_model_name = ctx.unique_name("sim2real-outmodel-")

    create_resp = _retry_transient(
        lambda: bedrock.create_model_customization_job(
            jobName=job_name,
            customModelName=custom_model_name,
            roleArn=role_arn,
            baseModelIdentifier=base_model_arn,
            trainingDataConfig={"s3Uri": f"s3://{bucket}/train/data.jsonl"},
            outputDataConfig={"s3Uri": f"s3://{bucket}/out/"},
            hyperParameters={"epochCount": "1", "learningRate": "0.0001"},
        )
    )
    job_arn = create_resp["jobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(bedrock, job_arn))

    initial = bedrock.get_model_customization_job(jobIdentifier=job_arn)
    assert initial["status"] in ("InProgress", "Stopping", "Stopped", "Completed", "Failed"), (
        f"expected CreateModelCustomizationJob to leave the job in a live or terminal "
        f"state, got {initial['status']!r}"
    )

    # Stop as soon as possible: a real fine-tuning job stays InProgress for many
    # minutes provisioning training compute, well past the time it takes us to issue
    # the stop call, so this is not racing a fast-failing job in practice.
    bedrock.stop_model_customization_job(jobIdentifier=job_arn)

    terminal_statuses = ("Stopped", "Completed", "Failed")
    status_history = []

    def _probe():
        resp = bedrock.get_model_customization_job(jobIdentifier=job_arn)
        status_history.append(resp["status"])
        return resp

    final = _poll_until(
        _probe,
        lambda r: r["status"] in terminal_statuses,
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert final["status"] == "Stopped", (
        f"expected StopModelCustomizationJob to drive the job to Stopped, got terminal "
        f"status {final['status']!r}; observed history={status_history!r}"
    )
    assert final["jobArn"] == job_arn, (
        f"GetModelCustomizationJob returned jobArn {final['jobArn']!r}, expected {job_arn!r}"
    )


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
    # us-east-1 is S3's own CreateBucket quirk (it rejects an explicit
    # LocationConstraint there), not a region pin for this resource.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
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
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _first_fine_tunable_model_arn(bedrock):
    resp = bedrock.list_foundation_models(byCustomizationType="FINE_TUNING")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
        # The check trains on {"prompt", "completion"} text pairs, so the base model
        # must be text-in/text-out — FINE_TUNING is also offered by embedding/image
        # models (e.g. titan-embed-image), which take a different training format.
        and "TEXT" in m.get("inputModalities", [])
        and "TEXT" in m.get("outputModalities", [])
    ]
    if not summaries:
        raise AssertionError(
            "no ACTIVE text-to-text foundation model in this account/region supports "
            "FINE_TUNING customization"
        )
    return summaries[0]["modelArn"]


def _best_effort_stop(bedrock, job_arn):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
