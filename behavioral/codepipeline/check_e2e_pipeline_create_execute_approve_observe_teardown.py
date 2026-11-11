"""e2e-pipeline-create-execute-approve-observe-teardown."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pipeline-create-execute-approve-observe-teardown"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipeline with a custom build and manual approval reaches Succeeded after PutApprovalResult
    with the GetPipelineState token; after delete, GetPipeline raises PipelineNotFoundException."""
    cp = ctx.client("codepipeline")
    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    _upload_source_zip(ctx, bucket, "source/source.zip")
    action_type_id = _register_custom_build_action(ctx)

    pipeline_name = ctx.unique_name("sim2real-cp-e2e-")
    stages = [
        _source_stage(bucket, "source/source.zip"),
        _build_stage(action_type_id),
        _approval_stage(),
    ]
    _create_pipeline(ctx, pipeline_name, role_arn, bucket, stages, register_delete_cleanup=True)

    execution_id = _settle_and_start(ctx, pipeline_name, stage_name="Build")
    job = _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=60.0)
    assert job is not None, f"execution {execution_id} never reached the Build action's job queue"
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    cp.put_job_success_result(jobId=job["id"])

    token = _wait_for_approval_token(ctx, pipeline_name)
    cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName="Approve",
        actionName="ApprovalAction",
        result={"summary": "sim2real approve", "status": "Approved"},
        token=token,
    )

    execution = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ],
        lambda ex: ex["status"] in ("Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert execution["status"] == "Succeeded", f"execution did not reach Succeeded: {execution}"

    state = cp.get_pipeline_state(name=pipeline_name)
    approve_state = next(s for s in state["stageStates"] if s["stageName"] == "Approve")
    assert approve_state["latestExecution"]["status"] == "Succeeded"

    cp.delete_pipeline(name=pipeline_name)
    refusal = _error_code(lambda: cp.get_pipeline(name=pipeline_name))
    assert refusal == (
        "PipelineNotFoundException",
        f"Account '{ctx.account}' does not have a pipeline with name '{pipeline_name}'",
    ), f"unexpected refusal after delete: {refusal}"



def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
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


def _upload_source_zip(ctx, bucket, key) -> None:
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral fixture\n")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _pipeline_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:GetBucketVersioning", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-inline"))
    return role_arn


def _register_custom_build_action(ctx):
    cp = ctx.client("codepipeline")
    provider = ("sim2realbld" + uuid.uuid4().hex)[:35]
    cp.create_custom_action_type(
        category="Build",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Build", provider=provider, version="1"))
    return {"category": "Build", "owner": "Custom", "provider": provider, "version": "1"}


def _source_stage(bucket, key):
    return {
        "name": "Source",
        "actions": [
            {
                "name": "SourceAction",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
            }
        ],
    }


def _build_stage(action_type_id):
    return {
        "name": "Build",
        "actions": [
            {
                "name": "BuildAction",
                "actionTypeId": action_type_id,
                "inputArtifacts": [{"name": "SourceOutput"}],
            }
        ],
    }


def _approval_stage():
    return {
        "name": "Approve",
        "actions": [
            {
                "name": "ApprovalAction",
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
            }
        ],
    }


def _create_pipeline(ctx, name, role_arn, bucket, stages, timeout_s=60.0, register_delete_cleanup=False):
    cp = ctx.client("codepipeline")
    decl = {"name": name, "roleArn": role_arn, "artifactStore": {"type": "S3", "location": bucket}, "stages": stages}
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = cp.create_pipeline(pipeline=decl, tags=[{"key": "sim2real-check", "value": CHECK}])
            if register_delete_cleanup:
                ctx.on_cleanup(lambda: _delete_pipeline_if_exists(ctx, name))
            return resp["pipeline"]
        except Exception as exc:  # IAM role/trust propagation is eventually consistent
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreatePipeline never succeeded: {last_err}")


def _delete_pipeline_if_exists(ctx, name) -> None:
    cp = ctx.client("codepipeline")
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=30.0, interval_s=3.0):
    """Poll for a job, accepting only one tied to this pipelineExecutionId.

    CreatePipeline auto-starts an execution whose job may be handed back first."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10).get("jobs", [])
        for job in jobs:
            if job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId") == execution_id:
                return job
        time.sleep(interval_s)
    return None


def _settle_and_start(ctx, pipeline_name, *, stage_name):
    """Start an execution behind a disabled inbound transition to supersede the auto-started one.

    Otherwise the auto-started execution holds `stage_name` forever with an unacknowledged job."""
    cp = ctx.client("codepipeline")
    cp.disable_stage_transition(
        pipelineName=pipeline_name,
        stageName=stage_name,
        transitionType="Inbound",
        reason="sim2real settling the CreatePipeline auto-triggered execution",
    )
    try:
        execution_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
        # Re-enable only once our execution reaches the boundary, or the older one slips in first.
        _wait_for_source_complete(ctx, pipeline_name, execution_id)
    finally:
        cp.enable_stage_transition(pipelineName=pipeline_name, stageName=stage_name, transitionType="Inbound")
    return execution_id


def _wait_for_source_complete(ctx, pipeline_name, execution_id, timeout_s=30.0, interval_s=1.0):
    cp = ctx.client("codepipeline")

    def probe():
        try:
            details = cp.list_action_executions(
                pipelineName=pipeline_name, filter={"pipelineExecutionId": execution_id}
            ).get("actionExecutionDetails", [])
        except ClientError as exc:
            # StartPipelineExecution's response precedes the execution's own read-path
            # visibility by a beat; a not-found here means "not yet", not "gone".
            if exc.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                return None
            raise
        return next((d for d in details if d.get("stageName") == "Source"), None)

    _poll_until(
        probe,
        lambda d: d is not None and d.get("status") == "Succeeded",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _wait_for_approval_token(ctx, pipeline_name, timeout_s=120.0):
    cp = ctx.client("codepipeline")

    def probe():
        state = cp.get_pipeline_state(name=pipeline_name)
        approve = next((s for s in state["stageStates"] if s["stageName"] == "Approve"), None)
        if not approve:
            return None
        action = next((a for a in approve.get("actionStates", []) if a["actionName"] == "ApprovalAction"), None)
        if not action:
            return None
        return action.get("latestExecution", {}).get("token")

    return _poll_until(probe, lambda t: t is not None, timeout_s=timeout_s, interval_s=3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

