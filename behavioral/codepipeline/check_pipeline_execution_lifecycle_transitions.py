"""pipeline-execution-lifecycle-transitions."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "pipeline-execution-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartPipelineExecution moves a pipeline InProgress -> Succeeded, observable via
    both GetPipelineExecution and GetPipelineState, driven end-to-end by a real custom
    action job worker (poll/ack/succeed) rather than a stub."""
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
                        "name": "Build",
                        "actionTypeId": action_type_id,
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "runOrder": 1,
                    }
                ],
            },
        ],
    )

    # CreatePipeline auto-starts an initial execution of its own. Drain it to a
    # terminal state (its Source action is AWS-native S3 and completes on its own;
    # its Build action needs a job worker) before starting the execution we actually
    # want to observe -- PollForJobs is not scoped to a pipelineExecutionId, so an
    # undrained initial execution's Build job is indistinguishable from ours.
    _drain_initial_execution(cp, pipeline_name, action_type_id)
    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

    # Immediately after starting, the execution must be observable as InProgress.
    # GetPipelineExecution can transiently 404 for a few hundred ms right after
    # StartPipelineExecution returns, so tolerate that as "not yet visible".
    def _probe_initial():
        try:
            return cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id)[
                "pipelineExecution"
            ]
        except cp.exceptions.PipelineExecutionNotFoundException:
            return None

    initial = _poll_until(
        _probe_initial,
        lambda pe: pe is not None and pe["status"] in ("InProgress", "Succeeded"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert initial["status"] == "InProgress", f"expected InProgress right after start, got {initial['status']}"

    # Drive the custom Build action to completion as the job worker.
    _drive_job(cp, action_type_id, exec_id, outcome="success", timeout_s=120.0)

    final = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id)[
            "pipelineExecution"
        ],
        lambda pe: pe["status"] in ("Succeeded", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final["status"] == "Succeeded", f"expected Succeeded, got {final['status']}"

    state = cp.get_pipeline_state(name=pipeline_name)
    stage_by_name = {s["stageName"]: s for s in state["stageStates"]}
    assert stage_by_name["Source"]["latestExecution"]["status"] == "Succeeded"
    assert stage_by_name["Build"]["latestExecution"]["status"] == "Succeeded"


def _drain_initial_execution(cp, pipeline_name: str, action_type_id: dict) -> None:
    """Drive CreatePipeline's auto-triggered execution to a terminal state by
    completing its Build job (there is exactly one execution in flight at this
    point, so any job for this action type is unambiguously its), then wait until
    ListPipelineExecutions shows nothing InProgress -- only then is starting a
    fresh execution race-free."""

    def probe():
        return cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", [])

    jobs = _poll_until(probe, lambda js: len(js) > 0, timeout_s=60.0, interval_s=2.0)
    job = jobs[0]
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    cp.put_job_success_result(jobId=job["id"])

    _poll_until(
        lambda: cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"],
        lambda execs: bool(execs) and all(e["status"] != "InProgress" for e in execs),
        timeout_s=60.0,
        interval_s=2.0,
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
        # S3 rejects a LocationConstraint that names the region CreateBucket already implies.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
        tags=[{"key": "sim2real", "value": "true"}],
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
            cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": "true"}])
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(5)

    def _cleanup():
        cp.delete_pipeline(name=name)
        try:
            cp.get_pipeline(name=name)
        except cp.exceptions.PipelineNotFoundException as exc:
            err = exc.response.get("Error", {})
            assert (err.get("Code"), err.get("Message")) == (
                "PipelineNotFoundException",
                f"Account '{ctx.account}' does not have a pipeline with name '{name}'",
            ), err
        else:
            raise AssertionError(f"expected pipeline {name!r} to be gone after delete_pipeline")

    ctx.on_cleanup(_cleanup)
    return name


def _drive_job(cp, action_type_id: dict, execution_id: str, outcome: str, timeout_s: float = 120.0):
    """Poll for a job, but only accept one tied to *this* pipelineExecutionId.

    CreatePipeline auto-starts an initial execution of its own, so the first job
    PollForJobs hands back may belong to that earlier execution rather than the one
    this check started -- filtering on data.pipelineContext.pipelineExecutionId keeps
    the two from being conflated."""

    def probe():
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10).get("jobs", [])
        for job in jobs:
            if job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId") == execution_id:
                return job
        return None

    job = _poll_until(probe, lambda j: j is not None, timeout_s=timeout_s, interval_s=3.0)
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
