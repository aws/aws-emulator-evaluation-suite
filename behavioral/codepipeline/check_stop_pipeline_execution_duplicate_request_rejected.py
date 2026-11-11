"""stop-pipeline-execution-duplicate-request-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-pipeline-execution-duplicate-request-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second StopPipelineExecution right after the first fails with PipelineExecutionNotStoppableException and
    its exact message, and the execution is Stopped.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_type_id, _ = _register_source_action_type(ctx, cp)
    pipeline_name = _create_source_and_approve_pipeline(ctx, cp, role_arn, bucket, source_type_id)

    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    # acknowledge (but never complete) the job so the action is genuinely InProgress
    # when the first stop is issued below
    job = _poll_for_job(cp, source_type_id)
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])

    def _force_abandon():
        try:
            cp.stop_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id, abandon=True, reason="cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "PipelineNotFoundException":
                raise

    ctx.on_cleanup(_force_abandon)

    # positive control: the first stop request succeeds
    cp.stop_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id, reason="first stop")

    # negative: a second stop request fired immediately after (no intervening poll) is
    # rejected -- the execution has already resolved to Stopped by the time it lands
    code, message = _error(
        lambda: cp.stop_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id, reason="second stop")
    )
    assert code == "PipelineExecutionNotStoppableException", f"expected PipelineExecutionNotStoppableException, got code={code!r}"
    assert message == (
        f"The pipeline execution with ID '{exec_id}' in '{pipeline_name}' can't be stopped now. "
        "Either it does not exist in the pipeline, or the pipeline execution has no action "
        "executions in progress."
    ), message

    # effect absent: the rejected duplicate request did not change the terminal status
    status_after = _poll_execution_status(cp, pipeline_name, exec_id, {"Stopped"})
    assert status_after == "Stopped", f"expected status Stopped, got {status_after!r}"


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
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
    s3.delete_bucket(Bucket=bucket)


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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


def _register_source_action_type(ctx, cp) -> tuple[dict, str]:
    provider = ctx.unique_name("CustSrc-")[:35]
    cp.create_custom_action_type(
        category="Source",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Source", provider=provider, version="1"))
    return {"category": "Source", "owner": "Custom", "provider": provider, "version": "1"}, provider


def _create_source_and_approve_pipeline(ctx, cp, role_arn: str, bucket: str, source_type_id: dict) -> str:
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
                "name": "Approve",
                "actions": [{
                    "name": "ApproveAction",
                    "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                }],
            },
        ],
    }
    _create_pipeline_with_retry(cp, definition)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))
    return pipeline_name


def _create_pipeline_with_retry(cp, definition: dict, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(pipeline=definition)
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"create_pipeline never succeeded (role propagation?): {last_err}")


def _poll_for_job(cp, action_type_id: dict, timeout_s: float = 40.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1)
        jobs = resp.get("jobs", [])
        if jobs:
            return jobs[0]
        time.sleep(1.5)
    raise AssertionError("no job appeared for action type within timeout")


def _poll_execution_status(cp, pipeline_name: str, exec_id: str, want_statuses: set, timeout_s: float = 40.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            status = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id)["pipelineExecution"]["status"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                # brief eventual-consistency window right after StartPipelineExecution
                time.sleep(1.0)
                continue
            raise
        if status in want_statuses:
            return status
        last = status
        time.sleep(1.5)
    raise AssertionError(f"execution never reached one of {want_statuses}; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
