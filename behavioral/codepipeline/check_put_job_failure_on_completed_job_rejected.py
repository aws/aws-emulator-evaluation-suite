"""put-job-failure-on-completed-job-rejected."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-job-failure-on-completed-job-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutJobFailureResult against a job that already reached a terminal state (Succeeded) is
    rejected with InvalidJobStateException, the action's status is not flipped to Failed, and a
    fresh job on the same pipeline can still be completed normally (positive control)."""
    cp = ctx.client("codepipeline")
    bucket, key = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    action_type_id = _create_custom_action_type(ctx)
    name = _create_pipeline(
        ctx, [_source_stage(bucket, key), _custom_build_stage(action_type_id)], role_arn, bucket
    )

    # CodePipeline auto-starts an execution the moment the pipeline is created; drain it
    # first so its Build job doesn't get interleaved with the execution we explicitly start.
    _drain_initial_execution(ctx, name, action_type_id)

    cp.start_pipeline_execution(name=name)
    job_id = _poll_and_acknowledge_job(ctx, action_type_id, timeout_s=180)
    cp.put_job_success_result(jobId=job_id)

    # Give the pipeline state a moment to reflect the completed action, then confirm terminal.
    _wait_for_action_status(ctx, name, "Build", "Build", "Succeeded", timeout_s=60)

    refusal = _error_code(lambda: cp.put_job_failure_result(jobId=job_id, failureDetails={"type": "JobFailed", "message": "late failure"}))
    assert refusal == (
        "InvalidJobStateException",
        f"Job with id {job_id} has already terminated",
    ), refusal

    # Effect absent: the action is still Succeeded, not flipped to Failed by the rejected call.
    status_after = _get_action_status(ctx, name, "Build", "Build")
    assert status_after == "Succeeded", status_after

    # Positive control: a fresh execution's job on the very same pipeline completes normally.
    cp.start_pipeline_execution(name=name)
    job_id_2 = _poll_and_acknowledge_job(ctx, action_type_id, timeout_s=180)
    cp.put_job_success_result(jobId=job_id_2)
    _wait_for_action_status(ctx, name, "Build", "Build", "Succeeded", timeout_s=60)


_PREFIX = "sim2real-cpbeh-"
_SCENARIO = "put-job-failure-on-completed-job-rejected"


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_bucket_name(ctx, base: str) -> str:
    raw = ctx.unique_name(base).lower()
    raw = re.sub(r"[^a-z0-9.-]", "-", raw)
    return raw[:63]


def _safe_token(ctx, base: str, maxlen: int) -> str:
    raw = re.sub(r"[^0-9A-Za-z_-]", "-", ctx.unique_name(base))
    return raw[-maxlen:] if len(raw) > maxlen else raw


def _make_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("buildspec.yml", "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n")
    return buf.getvalue()


def _create_artifact_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = _safe_bucket_name(ctx, _PREFIX + "art-")
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1; this branches on
    # ctx.region, it does not hardcode the bucket's region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    key = "source.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_make_zip_bytes())
    return bucket, key


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
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
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(_PREFIX + "role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetBucketVersioning", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="cp-inline", PolicyDocument=json.dumps(policy_doc))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="cp-inline")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_custom_action_type(ctx) -> dict[str, str]:
    cp = ctx.client("codepipeline")
    provider = _safe_token(ctx, "cpbprov-", 35)
    resp = cp.create_custom_action_type(
        category="Build",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 1},
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    )
    action_type_id = resp["actionType"]["id"]
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Build", provider=provider, version="1"))
    return action_type_id


def _source_stage(bucket: str, key: str) -> dict[str, Any]:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
                "runOrder": 1,
            }
        ],
    }


def _custom_build_stage(action_type_id: dict[str, str]) -> dict[str, Any]:
    return {
        "name": "Build",
        "actions": [
            {
                "name": "Build",
                "actionTypeId": action_type_id,
                "inputArtifacts": [{"name": "SourceOutput"}],
                "outputArtifacts": [{"name": "BuildOutput"}],
                "configuration": {},
                "runOrder": 1,
            }
        ],
    }


def _create_pipeline(ctx, stages: list[dict[str, Any]], role_arn: str, bucket: str, timeout_s: float = 90.0) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name(_PREFIX + "pipe-")
    pipeline_dict = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = cp.create_pipeline(
                pipeline=pipeline_dict, tags=[{"key": "sim2real", "value": _SCENARIO}]
            )
            ctx.on_cleanup(lambda n=name: cp.delete_pipeline(name=n))
            return resp["pipeline"]["name"]
        except ClientError as e:
            last_exc = e
            time.sleep(3)
    raise AssertionError(f"create_pipeline never succeeded: {last_exc}")


def _poll_and_acknowledge_job(ctx, action_type_id: dict[str, str], timeout_s: float = 180.0,
                              required: bool = True) -> str | None:
    """Poll for and acknowledge a job; with required=False, an empty queue at the deadline returns None."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1)
        jobs = resp.get("jobs", [])
        if jobs:
            job = jobs[0]
            cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
            return job["id"]
        time.sleep(3)
    if not required:
        return None
    raise AssertionError("no custom-action job appeared within timeout")


def _drain_initial_execution(ctx, pipeline_name: str, action_type_id: dict[str, str], timeout_s: float = 180.0) -> None:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs:
            break
        time.sleep(3)
    job_id = _poll_and_acknowledge_job(ctx, action_type_id, timeout_s=60, required=False)
    if job_id is not None:
        cp.put_job_success_result(jobId=job_id)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs and all(e["status"] != "InProgress" for e in execs):
            return
        time.sleep(3)
    raise AssertionError("initial auto-triggered pipeline execution never drained")


def _get_action_status(ctx, pipeline_name: str, stage_name: str, action_name: str) -> str | None:
    cp = ctx.client("codepipeline")
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state["stageStates"]:
        if stage["stageName"] != stage_name:
            continue
        for action in stage.get("actionStates", []):
            if action["actionName"] == action_name:
                return action.get("latestExecution", {}).get("status")
    return None


def _wait_for_action_status(ctx, pipeline_name: str, stage_name: str, action_name: str, expected: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _get_action_status(ctx, pipeline_name, stage_name, action_name)
        if last == expected:
            return
        time.sleep(3)
    raise AssertionError(f"action {stage_name}/{action_name} never reached {expected!r}, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
