"""list-action-executions-reflects-stage-sequence."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "list-action-executions-reflects-stage-sequence"
GROUP = "ordering"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListActionExecutions records start times in runOrder sequence, Source then ActionFirst (runOrder 1) then
    ActionLater (runOrder 2), although ActionLater is declared first, and all three Succeeded.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    action_type_id = _register_custom_action(ctx, category="Build")
    pipeline_name = _create_pipeline(
        ctx,
        role_arn,
        bucket,
        stages=[
            _source_stage(bucket),
            {
                "name": "Build",
                "actions": [
                    {
                        "name": "ActionLater",
                        "actionTypeId": action_type_id,
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "runOrder": 2,
                    },
                    {
                        "name": "ActionFirst",
                        "actionTypeId": action_type_id,
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "runOrder": 1,
                    },
                ],
            },
        ],
    )

    exec_id = _settle_and_start(cp, pipeline_name, stage_name="Build")

    _drive_job(cp, action_type_id, outcome="success", action_name="ActionFirst", timeout_s=90.0)
    _drive_job(cp, action_type_id, outcome="success", action_name="ActionLater", timeout_s=90.0)

    _poll_until(
        lambda: cp.get_pipeline_state(name=pipeline_name),
        lambda st: next(s for s in st["stageStates"] if s["stageName"] == "Build")["latestExecution"]["status"]
        == "Succeeded",
        timeout_s=90.0,
        interval_s=3.0,
    )

    details = cp.list_action_executions(
        pipelineName=pipeline_name, filter={"pipelineExecutionId": exec_id}
    )["actionExecutionDetails"]
    assert len(details) >= 3, f"expected Source + 2 Build actions, got {len(details)} records"

    by_name = {d["actionName"]: d for d in details}
    source_time = by_name["Source"]["startTime"]
    first_time = by_name["ActionFirst"]["startTime"]
    later_time = by_name["ActionLater"]["startTime"]

    # The actionExecutionDetails startTime values follow the runOrder-driven dispatch:
    # ActionFirst (runOrder=1) starts before ActionLater (runOrder=2), regardless of their
    # declaration order in the pipeline JSON.
    assert source_time <= first_time <= later_time, (
        f"recorded start times do not match the real run order: "
        f"source={source_time} first={first_time} later={later_time}"
    )

    # Each record must also carry the correct, matching status.
    assert by_name["Source"]["status"] == "Succeeded", f"Source status={by_name['Source']['status']!r}"
    assert by_name["ActionFirst"]["status"] == "Succeeded", f"ActionFirst status={by_name['ActionFirst']['status']!r}"
    assert by_name["ActionLater"]["status"] == "Succeeded", f"ActionLater status={by_name['ActionLater']['status']!r}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _settle_and_start(cp, pipeline_name: str, stage_name: str) -> str:
    """CreatePipeline auto-starts an initial execution. Disable inbound transition into
    the given stage, start our own execution, then re-enable -- the auto-triggered
    execution (if still queued to enter that stage) is superseded by ours, so exactly
    one execution (ours) ever reaches the stage. Re-enabling must wait for our own
    execution's Source stage to actually finish (so it is the one queued at the
    boundary) rather than a fixed sleep, or a slow Source leaves the older
    auto-triggered execution as the one that gets waved through on enable."""
    cp.disable_stage_transition(
        pipelineName=pipeline_name,
        stageName=stage_name,
        transitionType="Inbound",
        reason="sim2real settling the CreatePipeline auto-triggered execution",
    )
    try:
        exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

        def _source_latest():
            state = cp.get_pipeline_state(name=pipeline_name)
            source = next(s for s in state["stageStates"] if s["stageName"] == "Source")
            return source.get("latestExecution", {})

        _poll_until(
            _source_latest,
            lambda le: le.get("pipelineExecutionId") == exec_id and le.get("status") == "Succeeded",
            timeout_s=90.0,
            interval_s=2.0,
        )
    finally:
        cp.enable_stage_transition(pipelineName=pipeline_name, stageName=stage_name, transitionType="Inbound")
    return exec_id


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral check source artifact")
    return buf.getvalue()


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=_zip_bytes())
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "artifact-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:GetBucketVersioning",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    # No fixed wait for IAM propagation here: _create_pipeline already retries
    # CreatePipeline on any error for up to 60s, which absorbs the same lag.
    return role["Arn"]


def _register_custom_action(ctx, category="Build") -> dict:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("s2rW")[:35]
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))
    return {"category": category, "owner": "Custom", "provider": provider, "version": version}


def _source_stage(bucket: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "configuration": {
                    "S3Bucket": bucket,
                    "S3ObjectKey": "source.zip",
                    "PollForSourceChanges": "false",
                },
                "outputArtifacts": [{"name": "SourceOutput"}],
            }
        ],
    }


def _create_pipeline(ctx, role_arn: str, bucket: str, stages: list, pipeline_type=None) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pl-")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    if pipeline_type:
        pipeline["pipelineType"] = pipeline_type

    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline)
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _drive_job(cp, action_type_id: dict, outcome: str, timeout_s: float = 120.0, action_name: str | None = None):
    def probe():
        return cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=5).get("jobs", [])

    def find(jobs):
        if not jobs:
            return None
        if action_name is None:
            return jobs[0]
        for j in jobs:
            if j["data"]["pipelineContext"]["action"]["name"] == action_name:
                return j
        return None

    jobs = _poll_until(probe, lambda js: find(js) is not None, timeout_s=timeout_s, interval_s=3.0)
    job = find(jobs)
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    if outcome == "success":
        cp.put_job_success_result(jobId=job["id"])
    else:
        cp.put_job_failure_result(
            jobId=job["id"], failureDetails={"type": "JobFailed", "message": "sim2real forced failure"}
        )
    return job


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
