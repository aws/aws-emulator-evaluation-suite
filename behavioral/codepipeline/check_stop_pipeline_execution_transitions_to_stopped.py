"""stop-pipeline-execution-transitions-to-stopped."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "stop-pipeline-execution-transitions-to-stopped"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopPipelineExecution(abandon=True) moves an InProgress execution to a terminal
    Stopped state (per the documented abandon=true immediate transition) and marks the
    in-flight custom action Abandoned, observable via GetPipelineExecution/GetPipelineState."""
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

    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

    # CreatePipeline's own auto-triggered execution races ours into this custom action's
    # pull queue, so PollForJobs is not guaranteed to hand back our execution's job first.
    # Drain (ack) any job that belongs to a different execution and keep polling until the
    # job that belongs to `exec_id` is the one dispatched -- then leave THAT one hanging
    # (never ack/complete it) to force a real stop.
    job = _await_job_for_execution(cp, action_type_id, exec_id, timeout_s=120.0, interval_s=3.0)

    cp.stop_pipeline_execution(
        pipelineName=pipeline_name, pipelineExecutionId=exec_id, abandon=True, reason="sim2real stop test"
    )

    final = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id)[
            "pipelineExecution"
        ],
        lambda pe: pe["status"] in ("Stopped", "Succeeded", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final["status"] == "Stopped", f"expected Stopped, got {final['status']}"

    state = cp.get_pipeline_state(name=pipeline_name)
    build_stage = next(s for s in state["stageStates"] if s["stageName"] == "Build")
    build_action = next(a for a in build_stage["actionStates"] if a["actionName"] == "Build")
    assert build_action["latestExecution"]["status"] == "Abandoned", (
        f"expected the in-flight Build action to be Abandoned, got {build_action['latestExecution']['status']}"
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


def _await_job_for_execution(cp, action_type_id: dict, exec_id: str, *, timeout_s: float, interval_s: float) -> dict:
    """Drain (acknowledge, then complete) any polled job that does not belong to `exec_id`,
    so a leftover from the CreatePipeline auto-triggered execution can never be mistaken
    for the job under test. A job must be acknowledged before it can be completed or left
    hanging, so the one that IS ours is acknowledged too before we return it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", [])
        if jobs:
            job = jobs[0]
            cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
            if job["data"]["pipelineContext"]["pipelineExecutionId"] == exec_id:
                return job
            cp.put_job_success_result(jobId=job["id"])
        else:
            time.sleep(interval_s)
    raise AssertionError(f"no job for execution {exec_id} appeared within {timeout_s}s")



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
        # us-east-1 is a fixed S3 API quirk: CreateBucket rejects an explicit
        # LocationConstraint for that region and requires it to be omitted entirely.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
        tags=[{"key": "sim2real", "value": CHECK}],
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

    # Bounded retry absorbs IAM's own propagation delay: a role created moments ago can
    # still fail CodePipeline's assume-role check on the freshly-attached policy.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
