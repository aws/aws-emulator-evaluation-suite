"""action-execution-sequence-matches-stage-order."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "action-execution-sequence-matches-stage-order"
GROUP = "ordering"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListActionExecutions for a Source, Build and Approve execution, sorted by startTime, lists the actions in
    exactly the declared stage order.
    """
    cp = ctx.client("codepipeline")
    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    _upload_source_zip(ctx, bucket, "source/source.zip")
    action_type_id = _register_custom_build_action(ctx)

    pipeline_name = ctx.unique_name("sim2real-cp-seq-")
    stages = [
        _source_stage(bucket, "source/source.zip"),
        _build_stage(action_type_id),
        _approval_stage(),
    ]
    _create_pipeline(ctx, pipeline_name, role_arn, bucket, stages)

    execution_id, job = _run_pipeline_execution(ctx, pipeline_name, action_type_id)
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

    # GetPipelineExecution's aggregate status can lag the actual terminal state by
    # several minutes in real AWS -- far beyond this check's budget. GetPipelineState's
    # per-action latestExecution status is fast/responsive, so gate on that instead.
    _wait_for_action_state(ctx, pipeline_name, "Approve", "ApprovalAction", {"Succeeded", "Failed"})

    # ListActionExecutions is a separate historical-record read that can lag a few
    # seconds behind the action-level state above, so poll until all 3 entries land.
    details = _poll_until(
        lambda: cp.list_action_executions(
            pipelineName=pipeline_name, filter={"pipelineExecutionId": execution_id}
        )["actionExecutionDetails"],
        lambda d: len(d) >= 3,
        timeout_s=60.0,
        interval_s=3.0,
    )
    ordered = sorted(details, key=lambda d: d["startTime"])
    sequence = [(d["stageName"], d["actionName"]) for d in ordered]
    expected = [("Source", "SourceAction"), ("Build", "BuildAction"), ("Approve", "ApprovalAction")]
    assert sequence == expected, f"action execution order {sequence} != declared stage order {expected}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        tags=[{"key": "sim2real", "value": CHECK}],
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


def _create_pipeline(ctx, name, role_arn, bucket, stages, timeout_s=30.0):
    cp = ctx.client("codepipeline")
    decl = {"name": name, "roleArn": role_arn, "artifactStore": {"type": "S3", "location": bucket}, "stages": stages}
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = cp.create_pipeline(pipeline=decl, tags=[{"key": "sim2real", "value": CHECK}])
            ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
            return resp["pipeline"]
        except Exception as exc:  # IAM role/trust propagation is eventually consistent
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreatePipeline never succeeded: {last_err}")


def _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=30.0, interval_s=3.0):
    """Poll for a job, but only accept one tied to *this* pipelineExecutionId.

    CodePipeline auto-starts an initial execution as soon as CreatePipeline runs,
    so the first job PollForJobs hands back may belong to that earlier execution
    rather than the one this check just started -- filtering on
    data.pipelineContext.pipelineExecutionId keeps the two from being conflated.
    """
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10).get("jobs", [])
        for job in jobs:
            if job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId") == execution_id:
                return job
        time.sleep(interval_s)
    return None


def _run_pipeline_execution(ctx, pipeline_name, action_type_id, timeout_s=180.0):
    """Start our own execution and return (execution_id, job) for its own Build job.

    CreatePipeline auto-starts an initial execution. Left alone, that execution reaches the
    Build stage first and parks a job there that nothing ever acknowledges -- Build only
    holds one execution at a time, so our own execution then queues behind it forever and no
    job for OUR execution id ever appears (retrying StartPipelineExecution does not help: each
    retry supersedes the still-running Source stage). Disable inbound transition into Build, start our
    execution, then re-enable -- the newer execution supersedes the older on entry, so exactly
    one execution (ours) ever reaches Build.
    """
    cp = ctx.client("codepipeline")
    cp.disable_stage_transition(
        pipelineName=pipeline_name,
        stageName="Build",
        transitionType="Inbound",
        reason="sim2real settling the CreatePipeline auto-triggered execution",
    )
    try:
        execution_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
        # Re-enabling the Build transition only supersedes an older execution once ours has
        # actually cleared Source -- wait for that specific, observable condition rather than
        # a fixed sleep, so the settle window is exactly as long as it needs to be.
        _wait_for_action_state(ctx, pipeline_name, "Source", "SourceAction", {"Succeeded"}, timeout_s=120.0)
    finally:
        cp.enable_stage_transition(pipelineName=pipeline_name, stageName="Build", transitionType="Inbound")
    job = _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=timeout_s)
    if job is None:
        raise AssertionError(f"execution {execution_id} never reached the Build action's job queue")
    return execution_id, job


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


def _wait_for_action_state(ctx, pipeline_name, stage_name, action_name, target_statuses, timeout_s=120.0):
    cp = ctx.client("codepipeline")

    def probe():
        state = cp.get_pipeline_state(name=pipeline_name)
        stage = next((s for s in state["stageStates"] if s["stageName"] == stage_name), None)
        if not stage:
            return None
        action = next((a for a in stage.get("actionStates", []) if a["actionName"] == action_name), None)
        if not action:
            return None
        return action.get("latestExecution", {}).get("status")

    status = _poll_until(probe, lambda s: s in target_statuses, timeout_s=timeout_s, interval_s=3.0)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
