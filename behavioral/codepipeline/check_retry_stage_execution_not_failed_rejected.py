"""retry-stage-execution-not-failed-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "retry-stage-execution-not-failed-rejected"
GROUP = "server-side"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RetryStageExecution on a stage that has not failed is rejected; a genuinely failed stage can still be retried."""
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
                    "configuration": {},
                }],
            },
        ],
    }
    _create_pipeline_when_role_assumable(ctx, pipeline)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    # CreatePipeline auto-triggers an initial execution that shares the same
    # actionType-scoped PollForJobs queue as the execution under test. Drain it to a
    # terminal state first, or the two executions' jobs get crossed: our polling below
    # would service whichever execution's job happens to be queued, and the execution
    # we think we are tracking never receives one at all.
    initial_exec_id = _initial_execution_id(ctx, pipeline_name)
    initial_source_job = _poll_one_job(
        ctx, {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"}
    )
    _ack_and_succeed(ctx, initial_source_job)
    initial_build_job = _poll_one_job(ctx, build_action_type_id)
    _ack_and_succeed(ctx, initial_build_job)
    _poll_until_execution_status(ctx, pipeline_name, initial_exec_id, "Succeeded")

    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    assert exec_id != initial_exec_id

    source_job = _poll_one_job(
        ctx, {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"}
    )
    _ack_and_succeed(ctx, source_job)

    build_job = _poll_one_job(ctx, build_action_type_id)
    cp.acknowledge_job(jobId=build_job["id"], nonce=build_job["nonce"])
    status_before = _poll_until_action_status(ctx, pipeline_name, exec_id, "Build", "BuildAction", "InProgress")
    assert status_before == "InProgress"

    # Break exactly one thing: retry a stage that has not failed yet (it is still InProgress).
    code, message = _error(lambda: cp.retry_stage_execution(
        pipelineName=pipeline_name, stageName="Build", pipelineExecutionId=exec_id, retryMode="ALL_ACTIONS"
    ))
    assert code == "StageNotRetryableException", code
    expected = (
        f"The stage named Build in the {pipeline_name} pipeline can't be retried now. Either it contains no failed "
        f"actions, the execution '{exec_id}' is already superseded, or the pipeline definition has changed since "
        "the action(s) failed."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected retry did not disturb the in-progress action or spawn a
    # second job for the same action.
    status_after = _action_status(ctx, pipeline_name, exec_id, "Build", "BuildAction")
    assert status_after == "InProgress"
    stray = cp.poll_for_jobs(actionTypeId=build_action_type_id, maxBatchSize=1).get("jobs", [])
    assert stray == [], f"a spurious job appeared after the rejected retry: {stray}"

    # Now genuinely fail the stage, then confirm RetryStageExecution succeeds (positive control).
    cp.put_job_failure_result(
        jobId=build_job["id"], failureDetails={"type": "JobFailed", "message": "forced failure for test"}
    )
    failed_status = _poll_until_action_status(ctx, pipeline_name, exec_id, "Build", "BuildAction", "Failed")
    assert failed_status == "Failed"

    # The stage's action status can flip to Failed slightly before the pipeline execution's
    # internal retry-eligibility bookkeeping catches up; retry the RetryStageExecution call
    # itself on StageNotRetryableException within a bounded window rather than treating a
    # single immediate attempt as authoritative.
    _retry_stage_until_accepted(ctx, pipeline_name, exec_id, "Build")
    retried_job = _poll_one_job(ctx, build_action_type_id, timeout_s=60.0)
    assert retried_job["id"] != build_job["id"]
    _ack_and_succeed(ctx, retried_job)
    final_status = _poll_until_action_status(ctx, pipeline_name, exec_id, "Build", "BuildAction", "Succeeded")
    assert final_status == "Succeeded"


def _error(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError fn raises; fail loudly if the call succeeds."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError but the call succeeded")


def _create_pipeline_when_role_assumable(ctx, pipeline, timeout_s=60.0, interval_s=3.0):
    """CreatePipeline rejects a just-created role until IAM propagates it; retry only that rejection, bounded."""
    from botocore.exceptions import ClientError
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline)
            return
        except ClientError as err:
            error = err.response["Error"]
            propagating = error["Code"] == "InvalidStructureException" and "AssumeRole" in error.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]
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
    }
    if config_props:
        kwargs["configurationProperties"] = config_props
    cp.create_custom_action_type(**kwargs)
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))


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


def _initial_execution_id(ctx, pipeline_name, timeout_s=30.0, interval_s=2.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs:
            return execs[0]["pipelineExecutionId"]
        time.sleep(interval_s)
    raise AssertionError(f"no CreatePipeline-triggered execution appeared for {pipeline_name} within {timeout_s}s")


def _poll_until_execution_status(ctx, pipeline_name, execution_id, target, timeout_s=60.0, interval_s=2.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)["pipelineExecution"]["status"]
        if status == target:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"execution {execution_id} never reached {target}, last saw {status}")


def _action_status(ctx, pipeline_name, exec_id, stage_name, action_name):
    # GetPipelineState reflects the live action/job state near-instantly; ListActionExecutions
    # is a historical-record API with a much longer eventual-consistency lag, so it is not
    # suitable for polling in-flight InProgress state within a bounded test. actionStates[]
    # report the most recent attempt of that action directly (no separate per-pipelineExecution
    # scoping at the action level), which is exactly what a single, non-concurrent test needs.
    cp = ctx.client("codepipeline")
    resp = cp.get_pipeline_state(name=pipeline_name)
    for stage in resp.get("stageStates", []):
        if stage["stageName"] != stage_name:
            continue
        for action in stage.get("actionStates", []):
            if action["actionName"] == action_name:
                return action.get("latestExecution", {}).get("status")
    return None



def _poll_until_action_status(ctx, pipeline_name, exec_id, stage_name, action_name, target, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _action_status(ctx, pipeline_name, exec_id, stage_name, action_name)
        if status == target:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"action {stage_name}/{action_name} never reached {target}, last seen {status}")


def _retry_stage_until_accepted(ctx, pipeline_name, exec_id, stage_name, timeout_s=60.0, interval_s=3.0):
    from botocore.exceptions import ClientError
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cp.retry_stage_execution(
                pipelineName=pipeline_name, stageName=stage_name, pipelineExecutionId=exec_id, retryMode="ALL_ACTIONS"
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "StageNotRetryableException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"RetryStageExecution for {stage_name} never became acceptable within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
