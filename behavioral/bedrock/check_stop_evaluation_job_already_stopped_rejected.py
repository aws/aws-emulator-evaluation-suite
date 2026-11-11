"""stop-evaluation-job-already-stopped-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-evaluation-job-already-stopped-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopEvaluationJob on an InProgress job moves it to Stopped; a second stop returns
    ValidationException 'Evaluation job: <arn> is already in a stopped state.' and leaves its status and
    lastModifiedTime unchanged.
    """
    bedrock = ctx.client("bedrock")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-bedrock-eval-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    role_name = ctx.unique_name("sim2real-bedrock-eval-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    perms = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="eval-perms", PolicyDocument=json.dumps(perms))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="eval-perms"))

    model_arn = _first_on_demand_text_model_arn(bedrock)
    job_name = ctx.unique_name("sim2real-evaljob-")
    job_arn = _create_evaluation_job_with_iam_retry(
        bedrock, job_name=job_name, role_arn=role_arn, bucket=bucket, model_arn=model_arn
    )

    # positive control: stopping the job while it is genuinely InProgress succeeds and the
    # job settles in the terminal Stopped state.
    status_before_stop = bedrock.get_evaluation_job(jobIdentifier=job_arn)["status"]
    assert status_before_stop == "InProgress", f"expected InProgress, got {status_before_stop!r}"
    bedrock.stop_evaluation_job(jobIdentifier=job_arn)

    stopped = _poll_until(
        lambda: bedrock.get_evaluation_job(jobIdentifier=job_arn),
        lambda r: r["status"] in ("Stopped", "Completed", "Failed"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert stopped["status"] == "Stopped", f"expected the stopped job to end Stopped, got {stopped['status']!r}"
    stopped_at = stopped["lastModifiedTime"]

    # break exactly one thing: stop the terminal job a second time.
    code, message = _error_code(lambda: bedrock.stop_evaluation_job(jobIdentifier=job_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    assert message == f"Evaluation job: {job_arn} is already in a stopped state.", (
        f"expected the ValidationException to say the job is already stopped, got {message!r}"
    )

    # effect absent: the job is still Stopped, the rejected call did not change status
    # or advance the job's own reported lastModifiedTime.
    after = bedrock.get_evaluation_job(jobIdentifier=job_arn)
    assert after["status"] == "Stopped", f"expected status Stopped, got {after['status']!r}"
    assert after["lastModifiedTime"] == stopped_at, (
        f"lastModifiedTime advanced from {stopped_at!r} to {after['lastModifiedTime']!r} "
        "as a result of the rejected second stop call"
    )


def _error_code(fn):
    """Call fn() and return its error (code, message); a success raises, as the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


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


def _create_evaluation_job_with_iam_retry(
    bedrock, *, job_name, role_arn, bucket, model_arn, timeout_s=90.0
):
    # A freshly created IAM role is not always immediately assumable by the bedrock
    # service principal (IAM eventual consistency). Real AWS reports this as either
    # AccessDeniedException directly, or as a ValidationException whose message says
    # the assume-role call was denied -- retry only those two
    # shapes, so a genuinely malformed request still fails immediately.
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = bedrock.create_evaluation_job(
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
                inferenceConfig={
                    "models": [{"bedrockModel": {"modelIdentifier": model_arn}}]
                },
                outputDataConfig={"s3Uri": f"s3://{bucket}/eval-output/"},
            )
            return resp["jobArn"]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            role_not_yet_assumable = last_code == "AccessDeniedException" or (
                last_code == "ValidationException" and "assume roleArn" in message
            )
            if not role_not_yet_assumable:
                raise
            time.sleep(5.0)
    raise AssertionError(f"CreateEvaluationJob never succeeded (last error={last_code})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
