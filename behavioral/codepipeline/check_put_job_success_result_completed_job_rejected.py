"""put-job-success-result-completed-job-rejected."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-job-success-result-completed-job-rejected"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A repeated PutJobSuccessResult on a completed custom-action job answers HTTP 200, and the pipeline still
    shows exactly one Succeeded execution and an unchanged Build action execution history.
    """
    cp = ctx.client("codepipeline")
    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    _upload_source_zip(ctx, bucket, "source/source.zip")
    action_type_id = _register_custom_build_action(ctx)

    pipeline_name = ctx.unique_name("sim2real-cp-dupjob-")
    stages = [_source_stage(bucket, "source/source.zip"), _build_stage(action_type_id)]
    _create_pipeline(ctx, pipeline_name, role_arn, bucket, stages)

    execution_id, job = _run_pipeline_execution(ctx, pipeline_name, action_type_id)
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])

    # positive control: completing the job succeeds and the execution finishes
    cp.put_job_success_result(jobId=job["id"])
    execution = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ],
        lambda ex: ex["status"] in ("Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert execution["status"] == "Succeeded", f"positive control did not succeed: {execution}"
    before = _build_action_execution_ids(cp, pipeline_name, execution_id)
    assert len(before) == 1, f"expected exactly one Build action execution before the repeat: {before}"

    # repeating PutJobSuccessResult on the same, terminal jobId is a genuine 200,
    # not merely "did not raise" -- a bare try/except would also pass an emulator that
    # silently swallowed the call.
    repeat = cp.put_job_success_result(jobId=job["id"])
    assert repeat["ResponseMetadata"]["HTTPStatusCode"] == 200, f"unexpected repeat response: {repeat}"

    # effect absent: still exactly one pipeline execution and one Build action
    # execution, both Succeeded -- the idempotent repeat did not spawn a phantom one
    summaries = cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"]
    assert len(summaries) == 1, f"duplicate success call spawned extra executions: {summaries}"
    assert summaries[0]["pipelineExecutionId"] == execution_id
    assert summaries[0]["status"] == "Succeeded"
    after = _build_action_execution_ids(cp, pipeline_name, execution_id)
    assert after == before, f"duplicate success call changed the Build action execution history: {before} -> {after}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _build_action_execution_ids(cp, pipeline_name, execution_id):
    details = cp.list_action_executions(
        pipelineName=pipeline_name, filter={"pipelineExecutionId": execution_id}
    )["actionExecutionDetails"]
    return sorted(d["actionExecutionId"] for d in details if d["actionName"] == "BuildAction")


def _artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is S3's default region: CreateBucket rejects an explicit
    # LocationConstraint naming it, so the constraint is only ever sent elsewhere.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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


def _create_pipeline(ctx, name, role_arn, bucket, stages, timeout_s=30.0):
    cp = ctx.client("codepipeline")
    decl = {"name": name, "roleArn": role_arn, "artifactStore": {"type": "S3", "location": bucket}, "stages": stages}
    tags = [{"key": "sim2real", "value": "true"}]
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = cp.create_pipeline(pipeline=decl, tags=tags)
            ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
            return resp["pipeline"]
        except Exception as exc:  # IAM role/trust propagation is eventually consistent
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreatePipeline never succeeded: {last_err}")


def _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=15.0, interval_s=3.0):
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


def _run_pipeline_execution(ctx, pipeline_name, action_type_id, timeout_s=90.0):
    """CreatePipeline auto-triggers its own initial execution; wait for that one and
    return (execution_id, job) for its Build job. Calling StartPipelineExecution again
    would just queue a second, superseded execution behind the one already occupying
    the Build action's job slot, and its job would never surface."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    execution_id = None
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs:
            execution_id = execs[0]["pipelineExecutionId"]
            break
        time.sleep(2)
    if execution_id is None:
        raise AssertionError(f"no execution ever appeared for {pipeline_name}")
    job = _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=timeout_s)
    if job is None:
        raise AssertionError(f"execution {execution_id} never reached the Build action's job queue")
    return execution_id, job


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
