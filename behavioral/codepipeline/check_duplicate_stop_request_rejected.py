"""duplicate-stop-request-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-stop-request-rejected"
GROUP = "concurrency"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A back-to-back second StopPipelineExecution is rejected (DuplicatedStopRequestException or
    PipelineExecutionNotStoppableException), and the first stop still reaches Stopped."""
    cp = ctx.client("codepipeline")

    delay_seconds = 50
    lambda_arn = _create_delay_lambda(ctx, delay_seconds)
    role_arn = _create_service_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]
    )
    artifact_bucket = _create_bucket(ctx)
    source_bucket = _create_bucket(ctx, versioned=True)
    source_key = "src/app.zip"
    _put_zip_object(ctx, source_bucket, source_key, "app.txt", b"dup-stop-payload")

    name = ctx.unique_name("sim2real-cp-dupstop-")
    pipeline_decl = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [
            _source_stage(source_bucket, source_key),
            _delay_stage(lambda_arn),
        ],
    }
    _create_pipeline_with_role_propagation(
        cp, pipeline_decl, timeout_s=60.0, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_pipeline(cp, name))

    start_resp = _start_execution_with_backoff(cp, name)
    execution_id = start_resp["pipelineExecutionId"]

    _poll_until(
        lambda: _action_status(cp, name, "Delay", "Delay"),
        lambda s: s == "InProgress",
        timeout_s=90.0,
        interval_s=1.5,
    )

    cp.stop_pipeline_execution(
        pipelineName=name,
        pipelineExecutionId=execution_id,
        abandon=False,
        reason="sim2real-first-stop",
    )

    # CodePipeline can tear down the in-flight Lambda Invoke and reach Stopped before this
    # call lands, so the code depends on how far the first stop got.
    code, message = _error_code(
        lambda: cp.stop_pipeline_execution(
            pipelineName=name,
            pipelineExecutionId=execution_id,
            abandon=False,
            reason="sim2real-duplicate-stop",
        )
    )
    # The DuplicatedStopRequestException message is not pinned; only its code is asserted.
    expected_messages = {
        "DuplicatedStopRequestException": None,
        "PipelineExecutionNotStoppableException": (
            f"The pipeline execution with ID '{execution_id}' in '{name}' can't be stopped now. "
            "Either it does not exist in the pipeline, or the pipeline execution has no action "
            "executions in progress."
        ),
    }
    assert code in expected_messages, f"got {(code, message)!r}"
    if expected_messages[code] is not None:
        assert message == expected_messages[code], f"got {(code, message)!r}"

    status_after_duplicate = cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id
    )["pipelineExecution"]["status"]
    assert status_after_duplicate in ("Stopping", "InProgress", "Stopped"), (
        "the rejected duplicate stop must not have driven the execution anywhere "
        f"the first (legitimate) stop could not have on its own; got {status_after_duplicate!r}"
    )

    final_status = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ]["status"],
        lambda s: s in ("Stopped", "Failed", "Succeeded", "Superseded"),
        timeout_s=90.0,
        interval_s=2.0,
    )
    assert final_status == "Stopped", f"expected the original stop to reach Stopped, got {final_status!r}"




def _error_code(fn):
    """Call fn(); return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the duplicate stop request to be rejected, but it succeeded and returned {result!r}"
    )


def _create_pipeline_with_role_propagation(cp, declaration, *, timeout_s, tags=None):
    """Retry CreatePipeline while it answers InvalidStructureException for a still-propagating role.

    IAM exposes no condition to poll for role propagation, so the bounded retry is the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=declaration, tags=tags or [])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (
                err.get("Code") == "InvalidStructureException"
                and "AssumeRole" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _delete_pipeline(cp, name):
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _start_execution_with_backoff(cp, name: str, attempts: int = 5):
    """Start an execution, retrying ThrottlingException with backoff beyond botocore's budget.

    StartPipelineExecution can be throttled right after a pipeline is created or updated."""
    last_err = None
    for i in range(attempts):
        try:
            return cp.start_pipeline_execution(name=name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException"):
                last_err = e
                time.sleep(1.5 * (i + 1))
                continue
            raise
    raise AssertionError(f"start_pipeline_execution kept throttling: {last_err}")


def _source_stage(source_bucket: str, source_key: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {
                    "category": "Source",
                    "owner": "AWS",
                    "provider": "S3",
                    "version": "1",
                },
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {
                    "S3Bucket": source_bucket,
                    "S3ObjectKey": source_key,
                    "PollForSourceChanges": "false",
                },
            }
        ],
    }


def _delay_stage(lambda_arn: str) -> dict:
    function_name = lambda_arn.rsplit(":", 1)[-1]
    return {
        "name": "Delay",
        "actions": [
            {
                "name": "Delay",
                "actionTypeId": {
                    "category": "Invoke",
                    "owner": "AWS",
                    "provider": "Lambda",
                    "version": "1",
                },
                "configuration": {"FunctionName": function_name},
            }
        ],
    }


def _stage_state(state: dict, stage_name: str) -> dict:
    for s in state["stageStates"]:
        if s["stageName"] == stage_name:
            return s
    raise AssertionError(f"stage {stage_name} not found in pipeline state")


def _action_status(cp, pipeline_name: str, stage_name: str, action_name: str):
    state = cp.get_pipeline_state(name=pipeline_name)
    stage = _stage_state(state, stage_name)
    for action in stage.get("actionStates", []):
        if action["actionName"] == action_name:
            return action.get("latestExecution", {}).get("status")
    return None


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _zip_bytes(filename: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def _put_zip_object(ctx, bucket: str, key: str, filename: str, content: bytes) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=_zip_bytes(filename, content))


def _create_bucket(ctx, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    if versioned:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            _empty_bucket(ctx, bucket)
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _create_service_role(ctx, extra_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    statements = [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]
    if extra_statements:
        statements.extend(extra_statements)
    policy = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def _create_delay_lambda(ctx, delay_seconds: int) -> str:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-cp-lambdarole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["codepipeline:PutJobSuccessResult", "codepipeline:PutJobFailureResult"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )

    src = (
        "import time\n"
        "import boto3\n\n"
        f"DELAY_SECONDS = {delay_seconds}\n\n"
        "def handler(event, context):\n"
        "    time.sleep(DELAY_SECONDS)\n"
        "    job_id = event['CodePipeline.job']['id']\n"
        "    boto3.client('codepipeline').put_job_success_result(jobId=job_id)\n"
    )
    code_zip = _zip_bytes("index.py", src.encode("utf-8"))

    function_name = ctx.unique_name("sim2real-cp-delay-")

    def _cleanup_fn():
        try:
            lam.delete_function(FunctionName=function_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_fn)

    last_err = None
    deadline = time.monotonic() + 60.0
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role["Arn"],
                Handler="index.handler",
                Code={"ZipFile": code_zip},
                Timeout=max(60, delay_seconds + 30),
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")

    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda state: state == "Active",
        timeout_s=60.0,
        interval_s=2.0,
    )
    return resp["FunctionArn"]


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
