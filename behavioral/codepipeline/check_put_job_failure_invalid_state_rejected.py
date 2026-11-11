"""put-job-failure-invalid-state-rejected."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-job-failure-invalid-state-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]
_SCENARIO = "put-job-failure-invalid-state-rejected"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Calling PutJobFailureResult on a job already completed via
    PutJobSuccessResult is rejected with InvalidJobStateException rather than
    silently succeeding or re-flipping the job to Failed."""
    cp = ctx.client("codepipeline")
    src_type = _create_custom_action_type(ctx, "Source", 0, 0, 1, 1)
    build_type = _create_custom_action_type(ctx, "Build", 1, 1, 0, 1)
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": src_type,
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        },
        {
            "name": "Build",
            "actions": [
                {
                    "name": "BuildAction",
                    "actionTypeId": build_type,
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "outputArtifacts": [{"name": "BuildOutput"}],
                }
            ],
        },
    ]
    pipeline_name = _create_pipeline(ctx, stages)

    # --- negative: job already Succeeded, a failure result must be rejected ---
    exec1 = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    job = _poll_for_job(ctx, src_type, exec1)
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    s3 = ctx.client("s3")
    details = cp.get_job_details(jobId=job["id"])["jobDetails"]
    for artifact in details["data"].get("outputArtifacts", []):
        loc = (artifact.get("location") or {}).get("s3Location")
        if loc:
            s3.put_object(Bucket=loc["bucketName"], Key=loc["objectKey"], Body=_dummy_zip_bytes())
    cp.put_job_success_result(
        jobId=job["id"], currentRevision={"revision": "1", "changeIdentifier": _short_id()}
    )

    error = _error(
        lambda: cp.put_job_failure_result(
            jobId=job["id"], failureDetails={"type": "JobFailed", "message": "too-late"}
        )
    )
    assert error.get("Code") == "InvalidJobStateException", error
    expected_message = f"Job with id {job['id']} has already terminated"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # effect absent/present: the Source job's success already unblocked the
    # pipeline -- the Build stage's action gets dispatched as a new job for
    # THIS execution. This is a more reliable completion signal than polling
    # GetPipelineState's cached action status, and confirms the rejected
    # failure call had no effect (the pipeline kept moving forward from the
    # real Succeeded job).
    build_job = _poll_for_job(ctx, build_type, exec1, timeout_s=120, interval_s=4)
    assert build_job["data"]["pipelineContext"]["pipelineExecutionId"] == exec1, build_job

    # --- positive control: a legitimately InProgress job accepts a failure result ---
    exec2 = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    job2 = _poll_for_job(ctx, src_type, exec2)
    cp.acknowledge_job(jobId=job2["id"], nonce=job2["nonce"])
    cp.put_job_failure_result(
        jobId=job2["id"], failureDetails={"type": "JobFailed", "message": "expected-failure"}
    )
    state2 = _poll_until(
        lambda: _stage_status(cp, pipeline_name, "Source"),
        lambda s: s == "Failed",
        timeout_s=120,
        interval_s=4,
    )
    assert state2 == "Failed", state2


def _stage_status(cp, pipeline_name: str, stage_name: str) -> str | None:
    states = cp.get_pipeline_state(name=pipeline_name)["stageStates"]
    for s in states:
        if s["stageName"] == stage_name:
            return s.get("latestExecution", {}).get("status")
    raise AssertionError(f"stage {stage_name} not found in {states}")


def _dummy_zip_bytes() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("artifact.txt", "sim2real-behavioral-test-artifact")
    return buf.getvalue()


def _action_status(cp, pipeline_name: str, stage_name: str, action_name: str) -> str | None:
    states = cp.get_pipeline_state(name=pipeline_name)["stageStates"]
    for s in states:
        if s["stageName"] == stage_name:
            for a in s.get("actionStates", []):
                if a["actionName"] == action_name:
                    return a.get("latestExecution", {}).get("status")
            return None
    raise AssertionError(f"stage {stage_name} not found in {states}")


def _short_id() -> str:
    return uuid.uuid4().hex[:10]


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _poll_for_job(ctx, action_type_id: dict, exec_id: str, timeout_s=60.0, interval_s=3.0) -> dict:
    """Poll until a job belonging to `exec_id` appears. CodePipeline auto-starts
    an execution the instant the pipeline is created, and poll_for_jobs hands out
    jobs FIFO across every execution sharing this action type -- so a stale job
    from that auto-triggered execution (or an earlier explicit one) can come back
    first. Drain any such mismatch (as an unconditional success) rather than
    return it, so callers can trust the job they get is for their own execution."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", [])
        if jobs:
            job = jobs[0]
            if job["data"]["pipelineContext"]["pipelineExecutionId"] == exec_id:
                return job
            cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
            cp.put_job_success_result(jobId=job["id"])
            continue
        time.sleep(interval_s)
    raise AssertionError(f"no job for execution {exec_id!r} within {timeout_s}s")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # S3 CreateBucket API quirk: us-east-1 rejects an explicit LocationConstraint.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})

    def _cleanup():
        try:
            versions = s3.list_object_versions(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
            return
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = "artifact-access"
    policy = json.dumps(
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
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_custom_action_type(ctx, category: str, min_in: int, max_in: int, min_out: int, max_out: int):
    cp = ctx.client("codepipeline")
    provider = f"S2R{category[:2]}{_short_id()}"[:35]
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": min_in, "maximumCount": max_in},
        outputArtifactDetails={"minimumCount": min_out, "maximumCount": max_out},
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    )
    ctx.on_cleanup(
        lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version)
    )
    return {"category": category, "owner": "Custom", "provider": provider, "version": version}


def _create_pipeline(ctx, stages: list[dict], pipeline_type: str = "V1") -> str:
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-")
    pipeline_def: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    if pipeline_type == "V2":
        pipeline_def["pipelineType"] = "V2"

    # bounded retry: also covers IAM role-propagation lag, since a role that
    # CodePipeline cannot yet assume surfaces here as a ClientError.
    last_err: Exception | None = None
    for _ in range(6):
        try:
            cp.create_pipeline(
                pipeline=pipeline_def, tags=[{"key": "sim2real", "value": _SCENARIO}]
            )
            break
        except ClientError as e:
            last_err = e
            time.sleep(5)
    else:
        raise last_err  # type: ignore[misc]

    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
