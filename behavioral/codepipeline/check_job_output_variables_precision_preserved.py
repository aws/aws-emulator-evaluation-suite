"""job-output-variables-precision-preserved."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-output-variables-precision-preserved"
GROUP = "representation"
SERVICES = ["codepipeline"]

_LAMBDA_CODE = """
import json
import boto3

codepipeline = boto3.client("codepipeline")


def handler(event, context):
    job = event["CodePipeline.job"]
    job_id = job["id"]
    try:
        config = job["data"]["actionConfiguration"]["configuration"]
        output_vars = json.loads(config.get("UserParameters", "{}"))
        codepipeline.put_job_success_result(jobId=job_id, outputVariables=output_vars)
    except Exception as exc:  # noqa: BLE001
        codepipeline.put_job_failure_result(
            jobId=job_id, failureDetails={"type": "JobFailed", "message": str(exc)[:400]}
        )
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Numeric-string and unicode output variable values set via PutJobSuccessResult
    (from a Lambda invoke action job worker) are readable back byte-identical, with
    no numeric coercion or precision loss, via ListActionExecutions."""
    output_vars = {
        "BigInteger": "123456789012345678901234567890123456789",
        "PreciseDecimal": "3.14159265358979323846264338327950288",
        "UnicodeText": "h\u00e9llo-\u4e16\u754c-caf\u00e9",
    }

    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _upload_source_zip(ctx, bucket)
    fn_name = _create_lambda_function(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket, fn_name)
    name = ctx.unique_name("sim2real-cp-outvars-")

    pipeline_def = _pipeline_with_lambda_invoke(name, role_arn, bucket, key, fn_name, output_vars)
    _wait_role_usable(
        lambda: cp.create_pipeline(
            pipeline=pipeline_def, tags=[{"key": "sim2real", "value": CHECK}]
        )
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    # NOTE: CreatePipeline itself auto-starts an initial execution in addition to
    # the one StartPipelineExecution below explicitly starts. Under the default
    # SUPERSEDED execution mode, either could end up being the one that actually
    # drives the InvokeStage -- don't trust the exec_id StartPipelineExecution
    # hands back; read the actual driving pipelineExecutionId off the stage state.
    cp.start_pipeline_execution(name=name)

    def _probe_state() -> dict:
        return cp.get_pipeline_state(name=name)

    gated = _poll_until(
        _probe_state,
        lambda s: _stage_state(s, "InvokeStage").get("latestExecution") is not None,
        timeout_s=90.0,
    )
    exec_id = _stage_state(gated, "InvokeStage")["latestExecution"]["pipelineExecutionId"]

    def _probe() -> list[dict]:
        return cp.list_action_executions(
            pipelineName=name, filter={"pipelineExecutionId": exec_id}
        )["actionExecutionDetails"]

    def _latest_lambda_detail(details: list[dict]) -> dict | None:
        matches = [d for d in details if d["actionName"] == "InvokeLambda"]
        if not matches:
            return None
        return max(matches, key=lambda d: d["startTime"])

    def _lambda_action_done(details: list[dict]) -> bool:
        detail = _latest_lambda_detail(details)
        return detail is not None and detail["status"] in ("Succeeded", "Failed")

    details = _poll_until(_probe, _lambda_action_done, timeout_s=120.0)
    lambda_detail = _latest_lambda_detail(details)

    # The Lambda function's inline codepipeline:PutJobSuccessResult permission and the
    # pipeline role's lambda:InvokeFunction permission are both eventually consistent;
    # the InvokeLambda action can fail purely on that propagation lag. Bound the whole
    # recovery by a deadline and retry the stage -- never a blind pre-wait -- until it
    # succeeds or the deadline passes. RetryStageExecution reuses the same
    # pipelineExecutionId, so re-filtering on exec_id and taking the most-recently-started
    # InvokeLambda entry (by startTime) always reflects the latest retry's own outcome,
    # not a stale one.
    retry_deadline = time.monotonic() + 180.0
    while lambda_detail["status"] == "Failed" and time.monotonic() < retry_deadline:
        cp.retry_stage_execution(
            pipelineName=name,
            stageName="InvokeStage",
            pipelineExecutionId=exec_id,
            retryMode="FAILED_ACTIONS",
        )
        details = _poll_until(_probe, _lambda_action_done, timeout_s=120.0)
        lambda_detail = _latest_lambda_detail(details)

    assert lambda_detail["status"] == "Succeeded", (
        lambda_detail["status"],
        lambda_detail.get("output", {}).get("executionResult", {}).get("externalExecutionSummary"),
    )
    actual = lambda_detail["output"]["outputVariables"]
    assert actual == output_vars, (actual, output_vars)


def _stage_state(state_resp: dict, stage_name: str) -> dict:
    for stage in state_resp["stageStates"]:
        if stage["stageName"] == stage_name:
            return stage
    raise AssertionError(f"stage {stage_name} not found")


def _poll_until(probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _wait_role_usable(fn, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in (
                "InvalidStructureException",
                "InvalidParameterValueException",
                "InvalidRoleException",
                "ResourceConflictException",
            ) or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        resp = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_source_zip(ctx, bucket: str, key: str = "source.zip") -> str:
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real-behavioral-source")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return key


def _create_lambda_function(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-cp-lambdarole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    )
    policy_name = ctx.unique_name("sim2real-cp-lambdapolicy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["codepipeline:PutJobSuccessResult", "codepipeline:PutJobFailureResult"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _LAMBDA_CODE)

    fn_name = ctx.unique_name("sim2real-cp-outvars-fn-")

    def _create() -> None:
        ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
        lam.create_function(
            FunctionName=fn_name,
            Runtime="python3.12",
            Role=role["Arn"],
            Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=30,
            Tags={"sim2real": CHECK},
        )

    _wait_role_usable(_create)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _create_pipeline_role(ctx, bucket: str, fn_name: str) -> str:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codepipeline.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    fn_arn = lam.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]
    policy_name = ctx.unique_name("sim2real-cp-policy-")
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:PutObject",
                        "s3:GetBucketVersioning",
                        "s3:ListBucket",
                    ],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                },
                {"Effect": "Allow", "Action": ["lambda:InvokeFunction"], "Resource": fn_arn},
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _pipeline_with_lambda_invoke(
    name: str,
    role_arn: str,
    bucket: str,
    source_key: str,
    fn_name: str,
    output_vars: dict[str, str],
) -> dict:
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "SourceAction",
                        "actionTypeId": {
                            "category": "Source",
                            "owner": "AWS",
                            "provider": "S3",
                            "version": "1",
                        },
                        "outputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": {
                            "S3Bucket": bucket,
                            "S3ObjectKey": source_key,
                            "PollForSourceChanges": "false",
                        },
                        "runOrder": 1,
                    }
                ],
            },
            {
                "name": "InvokeStage",
                "actions": [
                    {
                        "name": "InvokeLambda",
                        "actionTypeId": {
                            "category": "Invoke",
                            "owner": "AWS",
                            "provider": "Lambda",
                            "version": "1",
                        },
                        "configuration": {
                            "FunctionName": fn_name,
                            "UserParameters": json.dumps(output_vars),
                        },
                        "runOrder": 1,
                    }
                ],
            },
        ],
    }


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
