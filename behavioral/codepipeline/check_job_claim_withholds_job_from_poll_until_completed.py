"""job-claim-withholds-job-from-poll-until-completed."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "job-claim-withholds-job-from-poll-until-completed"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codepipeline"]

# NOTE on scope: ActionDeclaration.timeoutInMinutes is documented as "available only to the
# manual approval ActionType" -- and empirically, CreatePipeline rejects timeoutInMinutes on a
# Custom Build action with InvalidActionDeclarationException. The non-configurable default
# action timeout for a Custom action is a fixed 24 hours (see CodePipeline quotas), which is far
# too long to wait out in a bounded test. What IS both reachable and a genuine visibility-window
# fidelity signal: once a job has been claimed (PollForJobs + AcknowledgeJob) but not yet
# completed, it must NOT be handed out again by a subsequent PollForJobs call for the same
# action type -- the claim gives exclusive, temporary ownership. GetJobDetails must keep
# reflecting that same claimed job throughout. Completing the job with PutJobSuccessResult is
# the positive control.


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A job claimed via PollForJobs+AcknowledgeJob is withheld from further PollForJobs calls until it is completed."""
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
    _create_pipeline_with_retry(cp, pipeline, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

    source_job = _poll_one_job(
        ctx, {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"}
    )
    _ack_and_succeed(ctx, source_job)

    claimed_job = _poll_one_job(ctx, build_action_type_id)
    cp.acknowledge_job(jobId=claimed_job["id"], nonce=claimed_job["nonce"])

    # The claimed-but-not-yet-completed job must be withheld from further polls: it is not
    # handed out again, and no *other* job for the same action type appears either (there is
    # only ever one live job per action instance at a time).
    for _ in range(3):
        still_out = cp.poll_for_jobs(actionTypeId=build_action_type_id, maxBatchSize=5).get("jobs", [])
        assert still_out == [], f"PollForJobs re-issued a job while one was already claimed: {still_out}"
        time.sleep(2.0)

    # GetJobDetails keeps reflecting the same claimed job throughout the claim window.
    details = cp.get_job_details(jobId=claimed_job["id"])["jobDetails"]
    assert details["id"] == claimed_job["id"], (
        f"GetJobDetails returned a different job id: expected {claimed_job['id']!r}, got {details['id']!r}"
    )
    assert details["data"]["actionTypeId"] == build_action_type_id, (
        f"GetJobDetails actionTypeId drifted: expected {build_action_type_id!r}, "
        f"got {details['data']['actionTypeId']!r}"
    )

    status_during_claim = _action_status(ctx, pipeline_name, exec_id, "Build", "BuildAction")
    assert status_during_claim == "InProgress", (
        f"expected the claimed action to read InProgress, got {status_during_claim!r}"
    )

    # Positive control: completing the claimed job normally lets the stage succeed, proving
    # the withheld job was never lost.
    cp.put_job_success_result(jobId=claimed_job["id"])
    final_status = _poll_until_action_status(ctx, pipeline_name, exec_id, "Build", "BuildAction", "Succeeded")
    assert final_status == "Succeeded", f"expected Succeeded after PutJobSuccessResult, got {final_status!r}"


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


def _create_pipeline_with_retry(cp, pipeline: dict, tags=None, timeout_s=60.0, interval_s=5.0) -> None:
    # IAM role/trust propagation lags CreatePipeline's role-assumability check; retry on that
    # transient rejection instead of guessing a fixed delay.
    kwargs = {"pipeline": pipeline}
    if tags:
        kwargs["tags"] = tags
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cp.create_pipeline(**kwargs)
            return
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


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
    kwargs["tags"] = [{"key": "sim2real", "value": CHECK}]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
