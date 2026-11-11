"""retry-stage-execution-stale-token-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-stage-execution-stale-token-rejected"
GROUP = "concurrency"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RetryStageExecution on a failed execution superseded by a newer in-flight one is rejected
    with StageNotRetryableException and changes nothing; retrying the latest failed execution
    succeeds and re-runs the Build action."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_type_id, _ = _register_action_type(ctx, cp, "Source", 0, 1)
    build_type_id, _ = _register_action_type(ctx, cp, "Build", 1, 0)
    pipeline_name = _create_source_build_pipeline(ctx, cp, role_arn, bucket, source_type_id, build_type_id)
    _discard_auto_triggered_execution(cp, pipeline_name)

    # PollForJobs does not scope by execution -- every _poll_for_job call below is filtered on
    # pipelineExecutionId so a stray job is never mistaken for exec1's/exec2's.
    exec1 = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    _complete_source(ctx, cp, pipeline_name, source_type_id, exec1, "rev-1")
    build_job1 = _poll_for_job(cp, build_type_id, exec1)
    cp.acknowledge_job(jobId=build_job1["id"], nonce=build_job1["nonce"])
    cp.put_job_failure_result(jobId=build_job1["id"], failureDetails={"type": "JobFailed", "message": "exec1 build failed"})
    _poll_stage_execution_status(cp, pipeline_name, "Build", exec1, "Failed")

    # execution 2: a fresh execution runs through Source and reaches Build, becoming the
    # new latest execution for the Build stage
    exec2 = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    _complete_source(ctx, cp, pipeline_name, source_type_id, exec2, "rev-2")
    build_job2 = _poll_for_job(cp, build_type_id, exec2)

    stage_latest = _get_stage_state(cp, pipeline_name, "Build")["latestExecution"]["pipelineExecutionId"]
    assert stage_latest == exec2, f"expected Build stage latestExecution to be exec2={exec2}, got {stage_latest}"

    # StageNotRetryableException, not NotLatestPipelineExecutionException, even while exec2's
    # Build attempt is still in flight.
    code, message = _error(
        lambda: cp.retry_stage_execution(pipelineName=pipeline_name, stageName="Build", pipelineExecutionId=exec1, retryMode="ALL_ACTIONS")
    )
    assert code == "StageNotRetryableException", f"expected StageNotRetryableException, got {code}"
    expected = (
        f"The stage named Build in the {pipeline_name} pipeline can't be retried now. Either it contains no failed "
        f"actions, the execution '{exec1}' is already superseded, or the pipeline definition has changed since "
        "the action(s) failed."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    stage_latest_after = _get_stage_state(cp, pipeline_name, "Build")["latestExecution"]["pipelineExecutionId"]
    assert stage_latest_after == exec2, (
        f"rejected retry must not move latestExecution off exec2={exec2}, got {stage_latest_after}"
    )
    # Only the execution-scoped action history can still describe exec1.
    exec1_action_status = _action_execution_status(cp, pipeline_name, exec1, "Build", "BuildAction")
    assert exec1_action_status == "Failed", (
        f"rejected retry must leave exec1's own Build action execution as Failed, got {exec1_action_status}"
    )

    cp.acknowledge_job(jobId=build_job2["id"], nonce=build_job2["nonce"])
    cp.put_job_failure_result(jobId=build_job2["id"], failureDetails={"type": "JobFailed", "message": "exec2 build failed"})
    _poll_stage_execution_status(cp, pipeline_name, "Build", exec2, "Failed")

    retry_resp = cp.retry_stage_execution(pipelineName=pipeline_name, stageName="Build", pipelineExecutionId=exec2, retryMode="ALL_ACTIONS")
    assert retry_resp["pipelineExecutionId"] == exec2, (
        f"expected retry of the now-latest exec2={exec2} to succeed and echo it back, got {retry_resp}"
    )
    retried_job = _poll_for_job(cp, build_type_id, exec2)
    assert retried_job["id"] != build_job2["id"], (
        f"expected a new job id for the retried Build action, got the same job id={retried_job['id']} as before the retry"
    )


def _error(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError fn raises; fail loudly if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_stage_execution_status(cp, pipeline_name: str, stage_name: str, exec_id: str, want_status: str, timeout_s: float = 90.0) -> None:
    """Poll the stage's latestExecution status in GetPipelineState: GetPipelineExecution's
    aggregate status can stay InProgress for minutes after the stage has gone Failed."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            latest = _get_stage_state(cp, pipeline_name, stage_name)["latestExecution"]
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ThrottlingException", "TooManyRequestsException"):
                time.sleep(1.5)
                continue
            raise
        if latest.get("pipelineExecutionId") == exec_id:
            last = latest.get("status")
            if last == want_status:
                return
        time.sleep(1.5)
    raise AssertionError(f"stage {stage_name} execution {exec_id} never reached status {want_status}; last={last}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    s3.delete_bucket(Bucket=bucket)


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:GetBucketVersioning", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="artifact-access", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="artifact-access"))
    return role_arn


def _register_action_type(ctx, cp, category: str, input_count: int, output_count: int) -> tuple[dict, str]:
    provider = ctx.unique_name(f"Cust{category}-")[:35]
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": input_count, "maximumCount": max(input_count, 1) if input_count else 0},
        outputArtifactDetails={"minimumCount": output_count, "maximumCount": max(output_count, 1) if output_count else 0},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version="1"))
    return {"category": category, "owner": "Custom", "provider": provider, "version": "1"}, provider


def _create_source_build_pipeline(ctx, cp, role_arn: str, bucket: str, source_type_id: dict, build_type_id: dict) -> str:
    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")
    definition = {
        "name": pipeline_name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": source_type_id,
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }],
            },
            {
                "name": "Build",
                "actions": [{
                    "name": "BuildAction",
                    "actionTypeId": build_type_id,
                    "inputArtifacts": [{"name": "SourceOutput"}],
                }],
            },
        ],
    }
    _create_pipeline_with_retry(cp, definition)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))
    return pipeline_name


def _discard_auto_triggered_execution(cp, pipeline_name: str, timeout_s: float = 20.0) -> None:
    """CreatePipeline auto-starts its own initial execution. Abandon it immediately so it can
    never occupy the Source stage or the Build stage's "latest execution" slot ahead of exec1."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs:
            for e in execs:
                if e["status"] in ("InProgress", "Stopping"):
                    cp.stop_pipeline_execution(
                        pipelineName=pipeline_name,
                        pipelineExecutionId=e["pipelineExecutionId"],
                        abandon=True,
                        reason="sim2real discarding CreatePipeline's auto-triggered execution",
                    )
            return
        time.sleep(1.0)
    raise AssertionError("CreatePipeline's auto-triggered execution never became visible to list_pipeline_executions")


def _create_pipeline_with_retry(cp, definition: dict, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(pipeline=definition, tags=[{"key": "sim2real", "value": CHECK}])
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"create_pipeline never succeeded (role propagation?): {last_err}")


def _poll_for_job(cp, action_type_id: dict, execution_id: str, timeout_s: float = 40.0) -> dict:
    """CreatePipeline auto-starts its own initial execution, so PollForJobs can hand back a job
    belonging to that execution instead of the one this check is driving. Filter on
    data.pipelineContext.pipelineExecutionId so the two are never conflated."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10).get("jobs", [])
        for job in jobs:
            if job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId") == execution_id:
                return job
        time.sleep(1.5)
    raise AssertionError(f"no job for execution {execution_id} appeared for action type within timeout")


def _action_execution_status(cp, pipeline_name: str, exec_id: str, stage_name: str, action_name: str) -> str | None:
    """ListActionExecutions filtered by pipelineExecutionId is scoped to that one execution,
    unlike GetPipelineState's stage-level "latestExecution" which always reflects whichever
    execution is CURRENTLY latest -- the only read that still speaks to a superseded execution."""
    details = cp.list_action_executions(
        pipelineName=pipeline_name, filter={"pipelineExecutionId": exec_id}
    ).get("actionExecutionDetails", [])
    match = next((d for d in details if d.get("stageName") == stage_name and d.get("actionName") == action_name), None)
    return match.get("status") if match else None


def _get_stage_state(cp, pipeline_name: str, stage_name: str) -> dict | None:
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state.get("stageStates", []):
        if stage["stageName"] == stage_name:
            return stage
    return None


def _get_action_state(cp, pipeline_name: str, stage_name: str, action_name: str) -> dict | None:
    stage = _get_stage_state(cp, pipeline_name, stage_name)
    if not stage:
        return None
    for action in stage.get("actionStates", []):
        if action["actionName"] == action_name:
            return action
    return None


def _poll_action_status(cp, pipeline_name: str, stage_name: str, action_name: str, want_status: str, timeout_s: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            action = _get_action_state(cp, pipeline_name, stage_name, action_name)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ThrottlingException", "TooManyRequestsException"):
                time.sleep(2.0)
                continue
            raise
        if action and action.get("latestExecution", {}).get("status") == want_status:
            return action
        last = action
        time.sleep(1.5)
    raise AssertionError(f"action {action_name} never reached status {want_status}; last={last}")


def _complete_source(ctx, cp, pipeline_name: str, source_type_id: dict, execution_id: str, revision: str) -> None:
    job = _poll_for_job(cp, source_type_id, execution_id)
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    _upload_output_artifact(ctx, job)
    cp.put_job_success_result(jobId=job["id"], currentRevision={"revision": revision, "changeIdentifier": revision})
    # Not polling the Source action's status: that view in GetPipelineState lags the stage
    # transition, so the caller polls for the downstream Build job instead.


def _upload_output_artifact(ctx, job: dict) -> None:
    out_artifacts = job.get("data", {}).get("outputArtifacts", [])
    if not out_artifacts:
        return
    creds = job["data"]["artifactCredentials"]
    s3 = ctx.client(
        "s3",
        creds={
            "aws_access_key_id": creds["accessKeyId"],
            "aws_secret_access_key": creds["secretAccessKey"],
            "aws_session_token": creds["sessionToken"],
        },
    )
    loc = out_artifacts[0]["location"]["s3Location"]
    s3.put_object(Bucket=loc["bucketName"], Key=loc["objectKey"], Body=b"PK\x05\x06" + b"\x00" * 18)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
