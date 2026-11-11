"""job-output-variables-value-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-output-variables-value-round-trip"
GROUP = "server-side"
SERVICES = ["codepipeline"]

_OUTPUT_VARIABLES = {
    "BuildNumber": "1042",
    "ExitCode": "-7",
    "Message": "50% off! <tag> & \"quoted\" \u2014 \u65e5\u672c\u8a9e \U0001f680",
}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Numeric/special-character outputVariables set via PutJobSuccessResult round-trip byte-identically through ListActionExecutions."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)

    source_provider = ctx.unique_name("sim2real-cp-src-")
    build_provider = ctx.unique_name("sim2real-cp-bld-")
    _create_custom_action_type(ctx, "Source", source_provider, "1", 0, 0, 1, 1)
    _create_custom_action_type(ctx, "Build", build_provider, "1", 1, 1, 0, 1)

    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")
    build_action_type_id = {"category": "Build", "owner": "Custom", "provider": build_provider, "version": "1"}
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
                    "actionTypeId": build_action_type_id,
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "namespace": "BuildVars",
                    "configuration": {},
                }],
            },
        ],
    }
    _create_pipeline_with_retry(ctx, pipeline, tags_=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    # CreatePipeline auto-starts an initial execution; poll_for_jobs is not scoped to a
    # pipelineExecutionId, so an un-drained auto-run can steal the ack meant for the
    # execution started below and strand this run's outputVariables on the wrong id.
    _drain_initial_execution(
        ctx,
        pipeline_name,
        {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"},
        build_action_type_id,
    )

    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

    source_job = _poll_one_job(
        ctx, {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"}
    )
    _ack_and_succeed(ctx, source_job)

    build_job = _poll_one_job(ctx, build_action_type_id)
    _ack_and_succeed(ctx, build_job, output_variables=_OUTPUT_VARIABLES)

    # GetPipelineState confirms the action itself completed near-instantly; ListActionExecutions
    # (used below for the actual outputVariables round-trip, since that's the only op that
    # surfaces them) is a historical-record API with a much longer eventual-consistency lag.
    _poll_until_stage_action_status(ctx, pipeline_name, exec_id, "Build", "BuildAction", "Succeeded", timeout_s=90.0)

    detail = _poll_until_action_output(ctx, pipeline_name, exec_id, "Build", "BuildAction", timeout_s=420.0, interval_s=8.0)
    returned_vars = detail["output"]["outputVariables"]
    assert returned_vars == _OUTPUT_VARIABLES, f"outputVariables changed in round trip: {returned_vars!r}"


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 rejects an explicit LocationConstraint for its own region.
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
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_custom_action_type(ctx, category, provider, version, in_min, in_max, out_min, out_max, config_props=None):
    cp = ctx.client("codepipeline")
    kwargs = {
        "category": category,
        "provider": provider,
        "version": version,
        "inputArtifactDetails": {"minimumCount": in_min, "maximumCount": in_max},
        "outputArtifactDetails": {"minimumCount": out_min, "maximumCount": out_max},
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    if config_props:
        kwargs["configurationProperties"] = config_props
    cp.create_custom_action_type(**kwargs)
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))


def _create_pipeline_with_retry(ctx, pipeline, tags_, timeout_s=60.0, interval_s=5.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline, tags=tags_)
            return
        except ClientError as exc:  # IAM role/trust-policy propagation is eventually consistent
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InvalidStructureException", "ValidationException", "InvalidParameterValueException"):
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _drain_initial_execution(ctx, pipeline_name, source_action_type_id, build_action_type_id):
    source_job = _poll_one_job(ctx, source_action_type_id)
    _ack_and_succeed(ctx, source_job)
    build_job = _poll_one_job(ctx, build_action_type_id)
    _ack_and_succeed(ctx, build_job)
    _poll_until_no_execution_in_progress(ctx, pipeline_name)


def _poll_until_no_execution_in_progress(ctx, pipeline_name, timeout_s=180.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    execs = []
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"]
        if execs and all(e["status"] != "InProgress" for e in execs):
            return
        time.sleep(interval_s)
    raise AssertionError(f"pipeline executions still InProgress after {timeout_s}s: {execs!r}")


def _poll_one_job(ctx, action_type_id, timeout_s=90.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1)
        jobs = resp.get("jobs", [])
        if jobs:
            return jobs[0]
        time.sleep(interval_s)
    raise AssertionError(f"no job appeared for actionTypeId={action_type_id} within {timeout_s}s")


def _ack_and_succeed(ctx, job, output_variables=None):
    cp = ctx.client("codepipeline")
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    kwargs = {"jobId": job["id"]}
    if output_variables:
        kwargs["outputVariables"] = output_variables
    cp.put_job_success_result(**kwargs)


def _poll_until_action_output(ctx, pipeline_name, exec_id, stage_name, action_name, timeout_s=60.0, interval_s=2.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.list_action_executions(
            pipelineName=pipeline_name, filter={"pipelineExecutionId": exec_id}, maxResults=100
        )
        for detail in resp.get("actionExecutionDetails", []):
            if (
                detail["stageName"] == stage_name
                and detail["actionName"] == action_name
                and detail.get("output", {}).get("outputVariables")
            ):
                return detail
        time.sleep(interval_s)
    raise AssertionError(f"outputVariables for {stage_name}/{action_name} never appeared within {timeout_s}s")


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
