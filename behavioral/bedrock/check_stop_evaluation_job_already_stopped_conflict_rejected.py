"""stop-evaluation-job-already-stopped-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stop-evaluation-job-already-stopped-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second StopEvaluationJob on a Stopped job is rejected and leaves it Stopped.

    The first Stop on the running job reaches Stopped (positive control); the second is refused
    with ValidationException naming the job as already in a stopped state.
    """
    bedrock = ctx.client("bedrock")
    job_arn = _start_evaluation_job(ctx)

    # Positive control: stopping a genuinely running job succeeds and reaches Stopped.
    bedrock.stop_evaluation_job(jobIdentifier=job_arn)

    def _probe():
        return bedrock.get_evaluation_job(jobIdentifier=job_arn)["status"]

    stopped_status = _poll_until(_probe, lambda s: s == "Stopped", timeout_s=600.0, interval_s=15.0)
    assert stopped_status == "Stopped", f"expected Stopped after the positive-control stop, got {stopped_status!r}"

    # Negative: stopping an already-terminal job is rejected. Real AWS returns
    # ValidationException naming the job as already stopped here, not ConflictException.
    error = _error(lambda: bedrock.stop_evaluation_job(jobIdentifier=job_arn))
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException naming the job as already stopped, got "
        f"{error['Code']!r}: {error.get('Message')!r}"
    )
    assert error.get("Message") == f"Evaluation job: {job_arn} is already in a stopped state.", (
        f"unexpected rejection message: {error.get('Message')!r}"
    )

    # Effect absent: the job's status did not change as a result of the rejected call.
    status_after = bedrock.get_evaluation_job(jobIdentifier=job_arn)["status"]
    assert status_after == "Stopped", f"expected status to remain Stopped after the rejected stop, got {status_after!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "stop-evaluation-job-already-stopped-conflict-rejected"}]},
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
        Tags=[{"Key": "sim2real", "Value": "stop-evaluation-job-already-stopped-conflict-rejected"}],
    )["Role"]["Arn"]
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
                "Action": "bedrock:InvokeModel",
                "Resource": "*",
            },
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


def _create_evaluation_job_with_role_propagation_retry(
    bedrock, *, job_name, role_arn, model_arn, bucket, timeout_s=90.0, interval_s=5.0
):
    # A freshly created IAM role/policy is not always immediately assumable by the bedrock
    # service principal. This surfaces as either AccessDeniedException or a ValidationException
    # whose message says "access denied ... attempting to assume roleArn" -- both are the same
    # transient IAM-propagation condition and are retried on the SAME model; any other
    # ValidationException (a model the account cannot use for evaluation) is not retried here.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return bedrock.create_evaluation_job(
                jobName=job_name,
                roleArn=role_arn,
                applicationType="ModelEvaluation",
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
                outputDataConfig={"s3Uri": f"s3://{bucket}/eval-out/"},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            is_role_propagation_lag = code == "AccessDeniedException" or (
                code == "ValidationException" and "assume roleArn" in message
            )
            if not is_role_propagation_lag:
                raise
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


def _on_demand_text_model_arn_candidates(bedrock):
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
        and m.get("providerName") == "Amazon"
    ]
    if not summaries:
        raise AssertionError(
            "no ACTIVE on-demand Amazon-provided text foundation model available in this "
            "account/region to evaluate"
        )
    # Not every Amazon on-demand text model is accepted by CreateEvaluationJob (e.g. the
    # Nova Sonic speech models are TEXT-output-capable but rejected for evaluation), so try
    # the Titan text family first and fall back through the rest rather than trusting the
    # first list entry.
    summaries.sort(key=lambda m: 0 if "titan-text" in m.get("modelId", "") else 1)
    return [m["modelArn"] for m in summaries]


def _start_evaluation_job(ctx):
    from botocore.exceptions import ClientError

    bedrock = ctx.client("bedrock")
    bucket = _create_bucket(ctx)
    role_arn = _create_bedrock_role(ctx, bucket)
    model_arns = _on_demand_text_model_arn_candidates(bedrock)

    job_name = ctx.unique_name("sim2real-evaljob-")
    last_exc = None
    for model_arn in model_arns:
        try:
            create_resp = _create_evaluation_job_with_role_propagation_retry(
                bedrock, job_name=job_name, role_arn=role_arn, model_arn=model_arn, bucket=bucket
            )
            return create_resp["jobArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationException":
                last_exc = e
                continue
            raise
    raise AssertionError(
        f"no candidate on-demand Amazon text model in this account/region is accepted by "
        f"CreateEvaluationJob; last error: {last_exc}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
