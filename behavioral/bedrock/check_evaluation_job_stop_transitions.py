"""evaluation-job-stop-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "evaluation-job-stop-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEvaluationJob starts a job; StopEvaluationJob transitions it to Stopped."""
    bedrock = ctx.client("bedrock")
    bucket = _create_scratch_bucket(ctx)
    role_arn = _create_bedrock_service_role(ctx, bucket)
    model_arn = _first_on_demand_text_model_arn(bedrock)

    job_name = ctx.unique_name("sim2real-evaljob-")

    def _create():
        return bedrock.create_evaluation_job(
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
            outputDataConfig={"s3Uri": f"s3://{bucket}/eval-output/"},
        )

    resp = _call_with_role_propagation_retry(_create)
    job_arn = resp["jobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(bedrock, job_arn))

    initial = bedrock.get_evaluation_job(jobIdentifier=job_arn)
    assert initial["status"] == "InProgress", (
        f"freshly-created evaluation job reported status {initial['status']!r}, expected InProgress"
    )

    bedrock.stop_evaluation_job(jobIdentifier=job_arn)

    terminal = ("Stopped", "Completed", "Failed")
    state = _poll_until(
        lambda: bedrock.get_evaluation_job(jobIdentifier=job_arn),
        lambda r: r["status"] in terminal,
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert state["status"] == "Stopped", f"job ended in {state['status']!r}, expected Stopped"
    assert state["jobArn"] == job_arn, f"GetEvaluationJob returned jobArn {state['jobArn']!r}, expected {job_arn!r}"


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-eval-")
    if ctx.region == "us-east-1":
        # S3 quirk, not a region pin: CreateBucket rejects an explicit LocationConstraint
        # of us-east-1, so that region alone must omit the parameter entirely.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="eval-access", PolicyDocument=json.dumps(policy))

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="eval-access")
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


def _first_on_demand_text_model_arn(bedrock) -> str:
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    ]
    if not summaries:
        raise AssertionError(
            "no ACTIVE on-demand text foundation model available in this account/region "
            "to evaluate"
        )
    return summaries[0]["modelArn"]


def _best_effort_stop(bedrock, job_arn: str) -> None:
    """Stop the job unless it is gone or already terminal; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        bedrock.stop_evaluation_job(jobIdentifier=job_arn)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if code not in ("ValidationException",):
            raise
        status = bedrock.get_evaluation_job(jobIdentifier=job_arn)["status"]
        if status not in ("Stopping", "Stopped", "Completed", "Failed", "Deleting"):
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
    assert last_err is not None, "retry loop exited without ever calling fn()"
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
