"""list-pipeline-executions-ordering-most-recent-first."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-pipeline-executions-ordering-most-recent-first"
GROUP = "ordering"
SERVICES = ["codepipeline"]
_SCENARIO = "codepipeline-list-executions-ordering-most-recent-first"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After two back-to-back executions reach Succeeded, ListPipelineExecutions lists the later
    one first, strictly ordered by startTime descending."""
    cp = ctx.client("codepipeline")
    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    _upload_source_zip(ctx, bucket, "source/source.zip")
    action_type_id = _register_custom_build_action(ctx)

    pipeline_name = ctx.unique_name("sim2real-cp-order-")
    stages = [_source_stage(bucket, "source/source.zip"), _build_stage(action_type_id)]
    _create_pipeline(ctx, pipeline_name, role_arn, bucket, stages)

    exec_id_1 = _run_to_completion(ctx, pipeline_name, action_type_id)
    exec_id_2 = _run_to_completion(ctx, pipeline_name, action_type_id)
    assert exec_id_1 != exec_id_2, f"two StartPipelineExecution calls returned the same id {exec_id_1!r}"

    summaries = cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"]
    ids = [s["pipelineExecutionId"] for s in summaries]
    assert exec_id_1 in ids and exec_id_2 in ids, f"expected {exec_id_1!r} and {exec_id_2!r} in {ids}"

    idx_1 = ids.index(exec_id_1)
    idx_2 = ids.index(exec_id_2)
    assert idx_2 < idx_1, f"second (later) execution {exec_id_2} not before first {exec_id_1} in {ids}"

    start_1 = next(s["startTime"] for s in summaries if s["pipelineExecutionId"] == exec_id_1)
    start_2 = next(s["startTime"] for s in summaries if s["pipelineExecutionId"] == exec_id_2)
    assert start_2 >= start_1, f"execution 2 startTime {start_2} is not >= execution 1 startTime {start_1}"



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
    # S3's CreateBucket rejects a LocationConstraint that matches us-east-1 (it is the API's
    # implicit default, not a resource pinned there) -- this is not a region pin.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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
        tags=[{"key": "sim2real", "value": _SCENARIO}],
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


def _create_pipeline(ctx, name, role_arn, bucket, stages, timeout_s=60.0):
    cp = ctx.client("codepipeline")
    decl = {"name": name, "roleArn": role_arn, "artifactStore": {"type": "S3", "location": bucket}, "stages": stages}
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = cp.create_pipeline(pipeline=decl, tags=[{"key": "sim2real", "value": _SCENARIO}])
            ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
            return resp["pipeline"]
        except Exception as exc:  # IAM role/trust propagation is eventually consistent
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreatePipeline never succeeded: {last_err}")


def _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=15.0, interval_s=3.0):
    """Poll for a job tied to this pipelineExecutionId, completing any other job found.

    A custom action's queue is head-blocked by an unresolved job from the auto-started execution."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10).get("jobs", [])
        for job in jobs:
            if job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId") == execution_id:
                return job
            cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
            cp.put_job_success_result(jobId=job["id"])
        time.sleep(interval_s)
    return None


def _run_to_completion(ctx, pipeline_name, action_type_id, timeout_s=300.0) -> str:
    cp = ctx.client("codepipeline")
    # Start exactly once: a newer execution supersedes an in-flight one at the same stage,
    # so restarting could keep any execution from reaching the Build job.
    execution_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    job = _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=timeout_s)
    if job is None:
        state = cp.get_pipeline_state(name=pipeline_name)
        raise AssertionError(
            f"execution {execution_id} never reached the Build action's job queue; state={state.get('stageStates')}"
        )
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    cp.put_job_success_result(jobId=job["id"])
    execution = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ],
        lambda ex: ex["status"] in ("Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert execution["status"] == "Succeeded", f"execution did not succeed: {execution}"
    return execution_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
