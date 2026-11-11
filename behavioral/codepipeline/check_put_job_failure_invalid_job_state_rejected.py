"""put-job-failure-invalid-job-state-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-job-failure-invalid-job-state-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutJobFailureResult fails an InProgress custom-action job, then a second PutJobFailureResult and a
    PutJobSuccessResult on it both fail with InvalidJobStateException and their exact messages, and the action
    stays Failed.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _put_source_object(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    action_type_id = _create_custom_action_type(ctx)
    name = ctx.unique_name("sim2real-cp-jobfail-")
    stages = [_source_stage(bucket, key), _custom_stage("Build", "RunBuild", action_type_id)]
    _create_pipeline(ctx, name, role_arn, bucket, stages)

    # CodePipeline auto-starts an execution the moment the pipeline is created; drain its
    # Build job first so it doesn't occupy the action and block the job for the execution
    # we explicitly start below.
    _drain_initial_execution(ctx, name, action_type_id)

    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    job = _poll_for_job(ctx, action_type_id, exec_id=exec_id)
    _acknowledge_job(ctx, job)

    # Positive control: failing an InProgress job works.
    cp.put_job_failure_result(
        jobId=job["id"], failureDetails={"type": "JobFailed", "message": "intentional failure"}
    )

    status = _poll_action_execution_status(ctx, name, exec_id, "RunBuild", timeout_s=180.0)
    assert status == "Failed"

    def _retry_failure():
        cp.put_job_failure_result(
            jobId=job["id"], failureDetails={"type": "JobFailed", "message": "second failure"}
        )

    refusal = _error_code(_retry_failure)
    assert refusal == (
        "InvalidJobStateException",
        f"The status of job with id {job['id']} is already set to the desired value. It cannot be "
        "updated with the same status, but different result or output variables.",
    ), refusal

    def _retry_success():
        cp.put_job_success_result(jobId=job["id"])

    refusal2 = _error_code(_retry_success)
    assert refusal2 == (
        "InvalidJobStateException",
        f"Job with id {job['id']} has already terminated",
    ), refusal2

    # Effect absent: the action stayed in its single Failed terminal state, not
    # resurrected to Succeeded by either rejected retry.
    status_after = _poll_action_execution_status(ctx, name, exec_id, "RunBuild", timeout_s=30.0)
    assert status_after == "Failed"


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
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
    return role_arn


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

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
            resp = cp.create_pipeline(pipeline=pipeline)
            break
        except ClientError as err:
            last_err = err
            # Also absorbs IAM role-to-CodePipeline propagation delay: the role from
            # _create_pipeline_role can be freshly created and not yet assumable.
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


def _poll_for_job(ctx, action_type_id: dict, exec_id: str | None = None, timeout_s: float = 180.0,
                  required: bool = True) -> dict | None:
    """Poll for a job; with required=False, an empty queue at the deadline returns None."""
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
    if not required:
        return None
    raise AssertionError("no job for the target execution appeared for the custom action within timeout")


def _acknowledge_job(ctx, job: dict) -> None:
    cp = ctx.client("codepipeline")
    resp = cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    assert resp["status"] == "InProgress"


def _drain_initial_execution(ctx, pipeline_name: str, action_type_id: dict, timeout_s: float = 180.0) -> None:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs:
            break
        time.sleep(3)
    job = _poll_for_job(ctx, action_type_id, timeout_s=60, required=False)
    if job is not None:
        _acknowledge_job(ctx, job)
        cp.put_job_success_result(jobId=job["id"])
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs and all(e["status"] != "InProgress" for e in execs):
            return
        time.sleep(3)
    raise AssertionError("initial auto-triggered pipeline execution never drained")


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
