"""pipeline-stage-actions-execute-in-declared-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "pipeline-stage-actions-execute-in-declared-order"
GROUP = "ordering"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Within one execution, ListActionExecutions timestamps confirm stages ran in declared order."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)

    source_provider = ctx.unique_name("sim2real-cp-src-")
    build_provider = ctx.unique_name("sim2real-cp-bld-")
    deploy_provider = ctx.unique_name("sim2real-cp-dpl-")
    _create_custom_action_type(ctx, "Source", source_provider, "1", 0, 0, 1, 1)
    _create_custom_action_type(ctx, "Build", build_provider, "1", 1, 1, 1, 1)
    _create_custom_action_type(ctx, "Deploy", deploy_provider, "1", 1, 1, 0, 1)

    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")
    pipeline = {
        "name": pipeline_name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {},
                }],
            },
            {
                "name": "Build",
                "actions": [{
                    "name": "BuildAction",
                    "actionTypeId": {"category": "Build", "owner": "Custom", "provider": build_provider, "version": "1"},
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "outputArtifacts": [{"name": "BuildOutput"}],
                    "configuration": {},
                }],
            },
            {
                "name": "Deploy",
                "actions": [{
                    "name": "DeployAction",
                    "actionTypeId": {"category": "Deploy", "owner": "Custom", "provider": deploy_provider, "version": "1"},
                    "inputArtifacts": [{"name": "BuildOutput"}],
                    "configuration": {},
                }],
            },
        ],
    }
    _create_pipeline_with_retry(ctx, pipeline)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    # CreatePipeline auto-starts its own initial execution immediately -- calling
    # StartPipelineExecution ourselves on top of that queues a second execution behind the
    # first at the (all-custom-action) Source stage, and since nobody services the first
    # execution's job under an exec_id filter, the second execution's Source job would never
    # be created and the check would deadlock. Drive the auto-triggered execution itself.
    exec_id = _wait_for_an_execution_id(ctx, pipeline_name)

    # Drive the pipeline strictly stage by stage: each PollForJobs call only returns a job
    # once the prior stage's action has been completed, so completing them in this order
    # is itself evidence that the service enforces declared ordering.
    for category, provider in (
        ("Source", source_provider),
        ("Build", build_provider),
        ("Deploy", deploy_provider),
    ):
        job = _poll_one_job(
            ctx, {"category": category, "owner": "Custom", "provider": provider, "version": "1"}, exec_id
        )
        _ack_and_succeed(ctx, job)

    # GetPipelineState reflects live state near-instantly; use it to confirm the whole
    # execution genuinely reached its terminal state before relying on ListActionExecutions,
    # which is a historical-record API with a much longer eventual-consistency lag.
    _poll_until_stage_action_status(ctx, pipeline_name, exec_id, "Deploy", "DeployAction", "Succeeded", timeout_s=90.0)

    details = _poll_until_action_count(ctx, pipeline_name, exec_id, 3, timeout_s=60.0, interval_s=5.0)
    by_stage = {d["stageName"]: d["startTime"] for d in details}
    assert set(by_stage) == {"Source", "Build", "Deploy"}, f"missing stage executions: {by_stage}"
    assert by_stage["Source"] < by_stage["Build"] < by_stage["Deploy"], (
        f"stage actions did not execute in declared order: {by_stage}"
    )


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:GetBucketVersioning", "s3:GetBucketAcl", "s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    })
    iam.put_role_policy(RoleName=role_name, PolicyName="artifact-access", PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="artifact-access"))
    return role["Arn"]


def _create_pipeline_with_retry(ctx, pipeline, timeout_s=60.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(pipeline=pipeline)
            return
        except Exception as exc:  # IAM role/trust propagation is eventually consistent
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreatePipeline never succeeded within {timeout_s}s (role/trust propagation?): {last_err}")


def _create_custom_action_type(ctx, category, provider, version, in_min, in_max, out_min, out_max, config_props=None):
    cp = ctx.client("codepipeline")
    kwargs = {
        "category": category,
        "provider": provider,
        "version": version,
        "inputArtifactDetails": {"minimumCount": in_min, "maximumCount": in_max},
        "outputArtifactDetails": {"minimumCount": out_min, "maximumCount": out_max},
    }
    if config_props:
        kwargs["configurationProperties"] = config_props
    cp.create_custom_action_type(**kwargs)
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))


def _wait_for_an_execution_id(ctx, pipeline_name, timeout_s=30.0, interval_s=2.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summaries = cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"]
        if summaries:
            return summaries[0]["pipelineExecutionId"]
        time.sleep(interval_s)
    raise AssertionError(f"pipeline {pipeline_name} never showed an auto-triggered execution within {timeout_s}s")


def _poll_one_job(ctx, action_type_id, exec_id, timeout_s=90.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10)
        for job in resp.get("jobs", []):
            if job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId") == exec_id:
                return job
        time.sleep(interval_s)
    raise AssertionError(
        f"no job for actionTypeId={action_type_id} tied to execution {exec_id} within {timeout_s}s"
    )


def _ack_and_succeed(ctx, job, output_variables=None):
    cp = ctx.client("codepipeline")
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    kwargs = {"jobId": job["id"]}
    if output_variables:
        kwargs["outputVariables"] = output_variables
    cp.put_job_success_result(**kwargs)


def _poll_until_action_count(ctx, pipeline_name, exec_id, count, timeout_s=60.0, interval_s=2.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    details = []
    while time.monotonic() < deadline:
        resp = cp.list_action_executions(
            pipelineName=pipeline_name, filter={"pipelineExecutionId": exec_id}, maxResults=100
        )
        details = resp.get("actionExecutionDetails", [])
        if len(details) >= count:
            return details
        time.sleep(interval_s)
    raise AssertionError(f"expected {count} action executions, saw {len(details)} within {timeout_s}s")


def _poll_until_stage_action_status(ctx, pipeline_name, exec_id, stage_name, action_name, target, timeout_s=90.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cp.get_pipeline_state(name=pipeline_name)
        for stage in resp.get("stageStates", []):
            if stage["stageName"] != stage_name:
                continue
            for action in stage.get("actionStates", []):
                if action["actionName"] == action_name:
                    status = action.get("latestExecution", {}).get("status")
        if status == target:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"{stage_name}/{action_name} never reached {target} via GetPipelineState, last seen {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
