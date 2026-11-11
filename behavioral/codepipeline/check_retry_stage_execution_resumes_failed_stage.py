"""retry-stage-execution-resumes-failed-stage."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-stage-execution-resumes-failed-stage"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RetryStageExecution(retryMode=FAILED_ACTIONS) re-dispatches only the action that
    failed in a stage, leaving the action that already succeeded untouched, and the
    stage/execution reach Succeeded once the retried action completes."""
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
                        "name": "ActionOK",
                        "actionTypeId": action_type_id,
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "runOrder": 1,
                    },
                    {
                        "name": "ActionFail",
                        "actionTypeId": action_type_id,
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "runOrder": 1,
                    },
                ],
            },
        ],
    )

    exec_id = _settle_and_start(cp, pipeline_name, stage_name="Build")

    _drive_job(cp, action_type_id, outcome="success", action_name="ActionOK", timeout_s=90.0)
    _drive_job(cp, action_type_id, outcome="failure", action_name="ActionFail", timeout_s=90.0)

    state = _poll_until(
        lambda: cp.get_pipeline_state(name=pipeline_name),
        lambda st: next(s for s in st["stageStates"] if s["stageName"] == "Build")["latestExecution"]["status"]
        == "Failed",
        timeout_s=90.0,
        interval_s=3.0,
    )
    build_stage = next(s for s in state["stageStates"] if s["stageName"] == "Build")
    action_ok_before = next(a for a in build_stage["actionStates"] if a["actionName"] == "ActionOK")
    ok_id_before = action_ok_before["latestExecution"]["actionExecutionId"]
    assert action_ok_before["latestExecution"]["status"] == "Succeeded"

    cp.retry_stage_execution(
        pipelineName=pipeline_name,
        stageName="Build",
        pipelineExecutionId=exec_id,
        retryMode="FAILED_ACTIONS",
    )

    # Only ActionFail must be re-dispatched; ActionOK must not receive a new job.
    job = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", []),
        lambda jobs: bool(jobs),
        timeout_s=60.0,
        interval_s=3.0,
    )[0]
    assert job["data"]["pipelineContext"]["action"]["name"] == "ActionFail"
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    cp.put_job_success_result(jobId=job["id"])

    final = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id)[
            "pipelineExecution"
        ],
        lambda pe: pe["status"] in ("Succeeded", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final["status"] == "Succeeded", f"expected Succeeded after retry, got {final['status']}"

    state = cp.get_pipeline_state(name=pipeline_name)
    build_stage = next(s for s in state["stageStates"] if s["stageName"] == "Build")
    action_ok_after = next(a for a in build_stage["actionStates"] if a["actionName"] == "ActionOK")
    assert action_ok_after["latestExecution"]["actionExecutionId"] == ok_id_before, (
        "ActionOK must not have been re-run by a FAILED_ACTIONS retry"
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
    """CreatePipeline auto-starts an initial execution. Disable inbound transition into
    the given stage, start our own execution, and wait until OUR OWN execution has
    Succeeded through Source -- a terminal state, not merely "latest" -- before
    re-enabling. Source only ever holds one execution at a time, so our execution
    cannot reach that terminal state until the auto-triggered one has already vacated
    Source (completed or been superseded); re-enabling on partial (in-progress)
    completion would race the two."""
    cp.disable_stage_transition(
        pipelineName=pipeline_name,
        stageName=stage_name,
        transitionType="Inbound",
        reason="sim2real settling the CreatePipeline auto-triggered execution",
    )
    try:
        exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

        def _source_settled(st):
            source = next(s for s in st["stageStates"] if s["stageName"] == "Source")
            latest = source.get("latestExecution", {})
            return latest.get("pipelineExecutionId") == exec_id and latest.get("status") == "Succeeded"

        _poll_until(
            lambda: cp.get_pipeline_state(name=pipeline_name),
            _source_settled,
            timeout_s=60.0,
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
        # us-east-1 is CreateBucket's implicit default: passing an explicit
        # LocationConstraint of "us-east-1" is itself rejected, so the literal here is
        # the API's own special case, not a region pin on the resource.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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

    # CreatePipeline validates that it can assume the role, so it answers
    # InvalidStructureException while the freshly created role is still propagating.
    # IAM exposes no condition to poll for that, so this bounded retry IS the wait --
    # there is no bare sleep standing in for it.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get("Message", "")
            if not transient or time.monotonic() >= deadline:
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
