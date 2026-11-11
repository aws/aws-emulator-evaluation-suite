"""put-job-success-invalid-job-state-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-job-success-invalid-job-state-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutJobSuccessResult on an unacknowledged custom-action job is rejected with
    InvalidJobStateException and leaves the action not Succeeded; after AcknowledgeJob the
    same call succeeds and the action completes."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _put_source_object(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    action_type_id = _create_custom_action_type(ctx)
    name = ctx.unique_name("sim2real-cp-jobok-")
    stages = [_source_stage(bucket, key), _custom_stage("Build", "RunBuild", action_type_id)]
    _create_pipeline(ctx, name, role_arn, bucket, stages)

    # CreatePipeline auto-triggers an initial execution whose job would occupy the custom
    # Build action's only job slot; drain it so PollForJobs returns the tracked execution's job.
    _drain_initial_execution(ctx, action_type_id)

    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    job = _poll_for_job(ctx, action_type_id, exec_id=exec_id)

    def _premature_success():
        cp.put_job_success_result(jobId=job["id"])

    code, message = _error_code(_premature_success)
    assert (code, message) == (
        "InvalidJobStateException",
        f"Job with id {job['id']} has not been acknowledged",
    ), f"unexpected refusal: {(code, message)!r}"

    status_before = _current_action_status(ctx, name, exec_id, "RunBuild")
    assert status_before != "Succeeded", f"action advanced despite rejected call: {status_before}"

    _acknowledge_job(ctx, job)
    cp.put_job_success_result(jobId=job["id"])

    status_after = _poll_action_execution_status(ctx, name, exec_id, "RunBuild", timeout_s=180.0)
    assert status_after == "Succeeded", f"expected Succeeded after the restored call, got {status_after}"


def _error_code(fn):
    try:
        fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError("expected fn() to raise a ClientError, but it succeeded")


def _poll_until(probe, predicate, timeout_s: float = 180.0, interval_s: float = 4.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last}")


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.txt", b"hello-sim2real")
    return buf.getvalue()


def _create_pipeline_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
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
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                }
            ],
        }
    )
    policy_name = "artifact-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    _wait_for_role_policy_visible(iam, role_name, policy_name)
    return role_arn


def _wait_for_role_policy_visible(iam, role_name: str, policy_name: str, timeout_s: float = 30.0) -> None:
    """Bounded poll for the inline policy read to reach IAM's own eventually-consistent
    replicas -- CodePipeline's own CreatePipeline retry loop already absorbs any residual
    cross-service propagation delay beyond that."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        if policy_name in names:
            return
        time.sleep(2)
    raise AssertionError(f"inline policy {policy_name!r} on role {role_name!r} never became visible")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower()
    # S3 CreateBucket API quirk, not a hardcoded target region: us-east-1 rejects an explicit
    # LocationConstraint, every other region requires one. The bucket still lands in ctx.region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup():
        versions = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_source_object(ctx, bucket: str, key: str = "source.zip") -> str:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=_zip_bytes())
    return key


def _source_stage(bucket: str, key: str) -> dict:
    action = {
        "name": "Source",
        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
        "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
        "outputArtifacts": [{"name": "SourceOutput"}],
    }
    return {"name": "Source", "actions": [action]}


def _create_custom_action_type(ctx, category: str = "Build") -> dict:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("Sim2RealJob").replace("-", "")[:35]
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version="1"))
    return {"category": category, "owner": "Custom", "provider": provider, "version": "1"}


def _custom_stage(stage_name: str, action_name: str, action_type_id: dict) -> dict:
    return {
        "name": stage_name,
        "actions": [
            {
                "name": action_name,
                "actionTypeId": action_type_id,
                "inputArtifacts": [{"name": "SourceOutput"}],
            }
        ],
    }


def _create_pipeline(ctx, name: str, role_arn: str, bucket: str, stages: list, pipeline_type: str = "V2",
                      execution_mode: str = "SUPERSEDED") -> dict:
    cp = ctx.client("codepipeline")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
        "pipelineType": pipeline_type,
        "executionMode": execution_mode,
    }
    last_err = None
    resp = None
    for _ in range(6):
        try:
            resp = cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real-check", "value": CHECK}])
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return resp["pipeline"]


def _get_action_state(cp, pipeline_name: str, stage_name: str, action_name: str):
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state["stageStates"]:
        if stage["stageName"] == stage_name:
            for action in stage.get("actionStates", []):
                if action["actionName"] == action_name:
                    return action
    return None


def _drain_initial_execution(ctx, action_type_id: dict, timeout_s: float = 60.0) -> None:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=5).get("jobs", [])
        if jobs:
            for job in jobs:
                cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
                cp.put_job_success_result(jobId=job["id"])
            return
        time.sleep(3)
    raise AssertionError("no job from the auto-triggered initial execution appeared to drain within timeout")


def _poll_for_job(ctx, action_type_id: dict, exec_id: str | None = None, timeout_s: float = 180.0) -> dict:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=5)
        jobs = resp.get("jobs", [])
        if jobs:
            if exec_id is None:
                return jobs[0]
            for job in jobs:
                if job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId") == exec_id:
                    return job
        time.sleep(4)
    raise AssertionError("no job for the target execution appeared for the custom action within timeout")


def _acknowledge_job(ctx, job: dict) -> None:
    cp = ctx.client("codepipeline")
    resp = cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    assert resp["status"] == "InProgress", f"expected InProgress after acknowledge, got {resp['status']}"


def _current_action_status(ctx, pipeline_name: str, exec_id: str, action_name: str) -> str | None:
    cp = ctx.client("codepipeline")
    resp = cp.list_action_executions(pipelineName=pipeline_name, filter={"pipelineExecutionId": exec_id})
    for detail in resp.get("actionExecutionDetails", []):
        if detail.get("actionName") == action_name:
            return detail.get("status")
    return None


def _poll_action_execution_status(ctx, pipeline_name: str, exec_id: str, action_name: str,
                                    timeout_s: float = 180.0, interval_s: float = 4.0) -> str:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cp.list_action_executions(
            pipelineName=pipeline_name, filter={"pipelineExecutionId": exec_id}
        )
        for detail in resp.get("actionExecutionDetails", []):
            if detail.get("actionName") == action_name:
                last = detail.get("status")
                if last in ("Succeeded", "Failed", "Abandoned"):
                    return last
        time.sleep(interval_s)
    raise AssertionError(f"action {action_name} execution status never settled; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
