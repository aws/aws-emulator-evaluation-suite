"""e2e-evaluation-job-with-guardrail-results-teardown."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-evaluation-job-with-guardrail-results-teardown"
GROUP = "e2e"
SERVICES = ["bedrock"]

_TERMINAL_JOB_STATUSES = {"Completed", "Failed", "Stopped"}


def _error(fn):
    """The Error dict fn() raises; an unexpected success raises AssertionError."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError("expected the call to fail, but it succeeded")


def _retry(fn, *, retryable_codes, timeout_s=60.0, interval_s=4.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retryable_codes:
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"operation never succeeded: {last_err}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not reach the expected state within {timeout_s}s; last={last!r}")


def _wait_guardrail_ready(bedrock, guardrail_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        if resp["status"] == "READY":
            return resp
        if resp["status"] == "FAILED":
            raise AssertionError(f"guardrail {guardrail_id} failed to become READY: {resp}")
        time.sleep(interval_s)
    raise AssertionError(f"guardrail {guardrail_id} never reached READY within {timeout_s}s")


def _wait_guardrail_version_ready(bedrock, guardrail_id, version, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)
        if resp["status"] == "READY":
            return resp
        if resp["status"] == "FAILED":
            raise AssertionError(f"guardrail version {version} failed to become READY: {resp}")
        time.sleep(interval_s)
    raise AssertionError(f"guardrail version {version} never reached READY within {timeout_s}s")


def _create_eval_role(ctx, iam, bucket_name):
    role_name = ctx.unique_name("sim2real-bedrock-eval-role-")
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel",
                    "bedrock:ApplyGuardrail",
                    "bedrock:GetGuardrail",
                    "bedrock:GetFoundationModel",
                    "bedrock:GetUseCaseForModelAccess",
                ],
                "Resource": "*",
            },
        ],
    }
    policy_name = f"{role_name}-inline"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """An evaluation job on a model with an account-enforced guardrail completes with the
    guardrail's blocked-output message in its S3 output; once deleted, GetEvaluationJob 404s."""
    bedrock = ctx.client("bedrock")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    existing_enforced = bedrock.list_enforced_guardrails_configuration()["guardrailsConfig"]
    if existing_enforced:
        raise AssertionError(
            "an account-level enforced-guardrail configuration already exists; "
            "mutating this singleton would clobber real account state"
        )

    model_id = "amazon.nova-lite-v1:0"
    model_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/{model_id}"

    bucket = ctx.unique_name("sim2real-bedrock-eval-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete_bucket() -> None:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)

    role_arn = _create_eval_role(ctx, iam, bucket)

    guardrail_name = ctx.unique_name("sim2real-eval-guardrail-")
    guardrail = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="This input is blocked by the evaluation guardrail.",
        blockedOutputsMessaging="This output is blocked by the evaluation guardrail.",
        contentPolicyConfig={
            "filtersConfig": [
                {"type": "HATE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                {"type": "INSULTS", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                {"type": "SEXUAL", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                {"type": "VIOLENCE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
            ]
        },
    )
    guardrail_id = guardrail["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))
    _wait_guardrail_ready(bedrock, guardrail_id)

    guardrail_version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)["version"]
    _wait_guardrail_version_ready(bedrock, guardrail_id, guardrail_version)

    enforced = bedrock.put_enforced_guardrail_configuration(
        guardrailInferenceConfig={
            "guardrailIdentifier": guardrail_id,
            "guardrailVersion": guardrail_version,
            "modelEnforcement": {"includedModels": [model_id], "excludedModels": []},
        }
    )
    enforced_config_id = enforced["configId"]
    ctx.on_cleanup(lambda: bedrock.delete_enforced_guardrail_configuration(configId=enforced_config_id))

    job_name = ctx.unique_name("sim2real-eval-job-")
    output_prefix = f"s3://{bucket}/eval-output/"
    # IAM propagation of the new role to bedrock.amazonaws.com is not fixed, so retry on the
    # codes that mean "not visible yet".
    job_arn = _retry(
        lambda: bedrock.create_evaluation_job(
            jobName=job_name,
            roleArn=role_arn,
            evaluationConfig={
                "automated": {
                    "datasetMetricConfigs": [
                        {
                            "taskType": "Generation",
                            "dataset": {"name": "Builtin.RealToxicityPrompts"},
                            "metricNames": ["Builtin.Toxicity"],
                        }
                    ]
                }
            },
            inferenceConfig={"models": [{"bedrockModel": {"modelIdentifier": model_arn}}]},
            outputDataConfig={"s3Uri": output_prefix},
        )["jobArn"],
        retryable_codes=("AccessDeniedException", "ValidationException"),
    )

    job_status = _poll_until(
        lambda: bedrock.get_evaluation_job(jobIdentifier=job_arn),
        lambda resp: resp["status"] in _TERMINAL_JOB_STATUSES,
        timeout_s=2700.0,
        interval_s=30.0,
        description=f"evaluation job {job_name}",
    )
    assert job_status["status"] == "Completed", (
        f"expected the guardrail-enforced evaluation job to complete, got {job_status['status']!r}: "
        f"{job_status.get('failureMessages')}"
    )

    blocked_marker = "This output is blocked by the evaluation guardrail."
    found_intervention = False
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix="eval-output/"):
        for obj in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            try:
                text = body.decode("utf-8", errors="ignore")
            except Exception:
                continue
            if blocked_marker in text:
                found_intervention = True
                break
        if found_intervention:
            break
    assert found_intervention, (
        "expected the enforced guardrail's blocked-output message to appear in the evaluation "
        "job's S3 output at least once, indicating the guardrail intervened during evaluation"
    )

    bedrock.batch_delete_evaluation_job(jobIdentifiers=[job_arn])

    not_found_message = f"Evaluation job {job_arn} does not exist. Please verify the job arn and retry."

    deadline = time.monotonic() + 300.0
    final_error = None
    while time.monotonic() < deadline:
        try:
            final_error = _error(lambda: bedrock.get_evaluation_job(jobIdentifier=job_arn))
        except AssertionError:
            final_error = None  # still gettable while the purge propagates
        if final_error is not None and final_error["Code"] == "ResourceNotFoundException":
            break
        time.sleep(2)
    assert final_error is not None and final_error["Code"] == "ResourceNotFoundException", (
        f"expected the evaluation job to become unreachable after BatchDeleteEvaluationJob, "
        f"last error was {final_error!r}"
    )
    assert final_error["Message"] == not_found_message, (
        f"expected GetEvaluationJob's not-found message {not_found_message!r}, got {final_error['Message']!r}"
    )

    remaining = bedrock.list_evaluation_jobs()["jobSummaries"]
    assert job_arn not in {j["jobArn"] for j in remaining}, (
        f"expected {job_arn} to be absent from ListEvaluationJobs after BatchDeleteEvaluationJob"
    )

    stop_error = _error(lambda: bedrock.stop_evaluation_job(jobIdentifier=job_arn))
    assert stop_error["Code"] == "ResourceNotFoundException", (
        f"expected StopEvaluationJob against the deleted job to fail with ResourceNotFoundException, "
        f"got {stop_error!r}"
    )
    assert stop_error["Message"] == not_found_message, (
        f"expected StopEvaluationJob's not-found message {not_found_message!r}, got {stop_error['Message']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
