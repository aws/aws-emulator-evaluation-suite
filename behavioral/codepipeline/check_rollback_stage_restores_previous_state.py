"""rollback-stage-restores-previous-state."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rollback-stage-restores-previous-state"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RollbackStage creates a ROLLBACK execution that reaches Succeeded with rollbackMetadata
    naming the prior successful target, leaving the rolled-back-from execution untouched."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    action_type_id = _register_custom_action(ctx, category="Deploy")
    pipeline_name = _create_pipeline(
        ctx,
        role_arn,
        bucket,
        stages=[
            _source_stage(bucket),
            {
                "name": "Deploy",
                "actions": [
                    {
                        "name": "Deploy",
                        "actionTypeId": action_type_id,
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "runOrder": 1,
                    }
                ],
            },
        ],
        pipeline_type="V2",
    )

    # Execution 1: succeeds fully -- this is the rollback target. CreatePipeline
    # auto-starts an execution of its own; settle that away so exec1 is the one and
    # only execution that reaches Deploy.
    exec1_id = _settle_and_start(cp, pipeline_name, stage_name="Deploy")

    _drive_job(cp, action_type_id, outcome="success", timeout_s=90.0)
    _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec1_id)[
            "pipelineExecution"
        ]["status"],
        lambda status: status in ("Succeeded", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    exec1_status = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec1_id)[
        "pipelineExecution"
    ]["status"]
    assert exec1_status == "Succeeded", f"rollback target execution {exec1_id} ended in {exec1_status!r}, not Succeeded"

    # Execution 2: the Deploy action fails (e.g. a bad deployment).
    exec2_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    _drive_job(cp, action_type_id, outcome="failure", timeout_s=90.0)
    _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec2_id)[
            "pipelineExecution"
        ]["status"],
        lambda status: status in ("Succeeded", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    exec2_status = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec2_id)[
        "pipelineExecution"
    ]["status"]
    assert exec2_status == "Failed", f"execution {exec2_id} to be rolled back away from ended in {exec2_status!r}, not Failed"

    rollback = cp.rollback_stage(
        pipelineName=pipeline_name, stageName="Deploy", targetPipelineExecutionId=exec1_id
    )
    rollback_id = rollback["pipelineExecutionId"]
    assert rollback_id not in (exec1_id, exec2_id), (
        f"RollbackStage must create a NEW execution id, got {rollback_id!r} which reuses "
        f"exec1={exec1_id!r} or exec2={exec2_id!r}"
    )

    _drive_job(cp, action_type_id, outcome="success", timeout_s=90.0)

    final = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=rollback_id)[
            "pipelineExecution"
        ],
        lambda pe: pe["status"] in ("Succeeded", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final["status"] == "Succeeded", f"rollback execution ended in {final['status']}"
    assert final["executionType"] == "ROLLBACK", (
        f"rollback execution {rollback_id} has executionType {final.get('executionType')!r}, expected 'ROLLBACK'"
    )
    assert final["rollbackMetadata"]["rollbackTargetPipelineExecutionId"] == exec1_id, (
        f"rollbackMetadata names target {final['rollbackMetadata'].get('rollbackTargetPipelineExecutionId')!r}, "
        f"expected the actual target {exec1_id!r}"
    )

    # Execution 2 (the failed run rolled back away from) must remain untouched.
    exec2_after = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec2_id)[
        "pipelineExecution"
    ]
    assert exec2_after["status"] == "Failed", (
        f"execution {exec2_id} was rolled back away from (not rolled back itself) and must stay "
        f"Failed, but now reports {exec2_after['status']!r}"
    )



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
    """Block the stage, start our execution, then re-enable, so our execution (not the one
    CreatePipeline auto-starts) is the only one that enters the stage."""
    cp.disable_stage_transition(
        pipelineName=pipeline_name,
        stageName=stage_name,
        transitionType="Inbound",
        reason="sim2real settling the CreatePipeline auto-triggered execution",
    )
    try:
        exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

        def _source_ready():
            state = cp.get_pipeline_state(name=pipeline_name)
            source = next((s for s in state["stageStates"] if s["stageName"] == "Source"), {})
            latest = source.get("latestExecution", {})
            return latest.get("pipelineExecutionId") == exec_id and latest.get("status") == "Succeeded"

        # Re-enabling before our Source stage Succeeded lets the auto-started execution win the race.
        _poll_until(_source_ready, lambda ready: ready, timeout_s=60.0, interval_s=2.0)
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
    # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
    # of "us-east-1", so the literal here is an S3 API quirk, not a region pin.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "cp-rollback-state"}]})

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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "cp-rollback-state"}],
    )["Role"]
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
    return role["Arn"]


def _register_custom_action(ctx, category="Deploy") -> dict:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("s2rW")[:35]
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        tags=[{"key": "sim2real", "value": "cp-rollback-state"}],
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

    # CreatePipeline validates that it can assume roleArn, so it answers
    # InvalidStructureException while the freshly created role/policy is still propagating.
    # IAM exposes no condition to poll for that, so the bounded retry is the wait.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": "cp-rollback-state"}])
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get("Message", "")
            if not transient or time.monotonic() > deadline:
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
