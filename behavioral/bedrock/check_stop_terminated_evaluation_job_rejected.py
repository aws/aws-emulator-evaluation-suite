"""stop-terminated-evaluation-job-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-terminated-evaluation-job-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopEvaluationJob on an already Stopped job is rejected with a ValidationException naming
    the job as already stopped, not accepted as a silent no-op; the status stays Stopped."""
    bedrock = ctx.client("bedrock")
    bucket = _create_scratch_bucket(ctx)
    role_arn = _create_bedrock_service_role(ctx, bucket)
    model_arns = _on_demand_text_model_arn_candidates(bedrock)

    def _create_job(name: str, model_arn: str) -> str:
        try:
            resp = _call_with_role_propagation_retry(
                lambda: bedrock.create_evaluation_job(
                    jobName=name,
                    roleArn=role_arn,
                    jobTags=[{"key": "sim2real-check", "value": CHECK}],
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
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "AccessDeniedException" and "cross-account pass role" in msg.lower():
                raise AssertionError(
                    "this verification environment's calling session cannot "
                    "iam:PassRole any roleArn to Bedrock (doubly-assumed role "
                    f"chain), so CreateEvaluationJob can never succeed here: {msg}"
                ) from err
            raise
        return resp["jobArn"]

    job_name = ctx.unique_name("sim2real-bedrock-eval-")
    job_arn = None
    last_err = None
    for model_arn in model_arns:
        try:
            job_arn = _create_job(job_name, model_arn)
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "ValidationException":
                raise
            last_err = err
    if job_arn is None:
        raise AssertionError(
            f"no candidate on-demand Amazon text model is accepted by CreateEvaluationJob: {last_err}"
        )
    ctx.on_cleanup(lambda: _safe_stop_eval(bedrock, job_arn))

    # positive control: stopping a genuinely running job succeeds and reaches Stopped.
    bedrock.stop_evaluation_job(jobIdentifier=job_arn)
    status = _wait_for_eval_status(bedrock, job_arn, {"Stopped", "Failed", "Completed"}, timeout_s=900)
    if status != "Stopped":
        raise AssertionError(
            f"evaluation job reached terminal status {status!r} instead of "
            "Stopped before we could exercise the double-stop; cannot assert "
            "the already-terminal Stop rejection from this state"
        )

    # break exactly one thing: stop the now-terminal job a second time.
    code, message = _error(lambda: bedrock.stop_evaluation_job(jobIdentifier=job_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    assert message == f"Evaluation job: {job_arn} is already in a stopped state.", (
        f"unexpected rejection message: {message!r}"
    )

    # effect absent: status is unchanged, still Stopped
    status_after = bedrock.get_evaluation_job(jobIdentifier=job_arn)["status"]
    assert status_after == "Stopped", f"expected status to remain Stopped, got {status_after!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _on_demand_text_model_arn_candidates(bedrock) -> list[str]:
    """ACTIVE on-demand Amazon text models, Titan text first; not every one is accepted by
    CreateEvaluationJob, so the caller tries them in order."""
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE" and m.get("providerName") == "Amazon"
    ]
    if not summaries:
        raise AssertionError("no ACTIVE on-demand Amazon text foundation model to evaluate")
    summaries.sort(key=lambda m: 0 if "titan-text" in m.get("modelId", "") else 1)
    return [m["modelArn"] for m in summaries]


def _safe_stop_eval(bedrock, job_arn: str) -> None:
    """Stop the job unless it is gone or already terminal; any other failure raises."""
    try:
        bedrock.stop_evaluation_job(jobIdentifier=job_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if code != "ValidationException":
            raise
        status = bedrock.get_evaluation_job(jobIdentifier=job_arn)["status"]
        if status not in ("Stopping", "Stopped", "Completed", "Failed"):
            raise


def _wait_for_eval_status(bedrock, job_arn: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = ""
    while time.monotonic() < deadline:
        status = bedrock.get_evaluation_job(jobIdentifier=job_arn)["status"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"evaluation job never reached a terminal status, last={status}")


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-evalneg-").lower().replace("_", "-")
    # us-east-1 is CreateBucket's default region; passing it as a LocationConstraint is rejected.
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
            },
            {
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="eval-access", PolicyDocument=json.dumps(policy)
    )

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


def _call_with_role_propagation_retry(
    fn: Callable[[], Any], *, timeout_s: float = 90.0, interval_s: float = 5.0
) -> Any:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "AccessDeniedException" and "cross-account pass role" in msg.lower():
                # Permanent (a session-nesting artifact, not IAM propagation lag) --
                # retrying would just burn the timeout budget waiting on a condition
                # that will never clear.
                raise
            # A fresh role is not always assumable at once: AccessDeniedException, or a
            # ValidationException about assuming roleArn. Any other rejection is final.
            if code == "AccessDeniedException" or (
                code == "ValidationException" and "assume roleArn" in msg
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "retry loop exited without ever calling fn()"
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
