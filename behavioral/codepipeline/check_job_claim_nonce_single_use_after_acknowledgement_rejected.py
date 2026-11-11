"""job-claim-nonce-single-use-after-acknowledgement-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "job-claim-nonce-single-use-after-acknowledgement-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a nonce already consumed by AcknowledgeJob fails, and the original claim is unaffected."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)

    source_provider = ctx.unique_name("sim2real-cp-src-")
    build_provider = ctx.unique_name("sim2real-cp-bld-")
    _create_custom_action_type(ctx, "Source", source_provider, "1", 0, 0, 1, 1)
    _create_custom_action_type(ctx, "Build", build_provider, "1", 1, 1, 0, 1)

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
                    "configuration": {},
                }],
            },
        ],
    }
    _create_pipeline_with_retry(ctx, pipeline_name, pipeline)

    action_type_id = {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"}
    job = _poll_one_job(ctx, action_type_id)
    exec_id = job["data"]["pipelineContext"]["pipelineExecutionId"]

    # Positive control: the first acknowledgement with the freshly issued nonce succeeds.
    ack1 = cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    assert ack1["status"] == "InProgress"

    # GetPipelineState is near-instantly consistent with the job-claim state change.
    status_before = _poll_until_action_status(ctx, pipeline_name, exec_id, "Source", "SourceAction", "InProgress")
    assert status_before == "InProgress"

    # Empirically, re-acknowledging with the SAME (still-valid) nonce while the job is still
    # InProgress is idempotent on real AWS -- it is not rejected. The nonce is only invalidated
    # once the job leaves the "awaiting acknowledgement/completion" window, i.e. after it has
    # been completed.
    ack_repeat = cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    assert ack_repeat["status"] == "InProgress"

    # Complete the job -- this closes its single-use claim window.
    cp.put_job_success_result(jobId=job["id"])
    final_status = _poll_until_action_status(ctx, pipeline_name, exec_id, "Source", "SourceAction", "Succeeded")
    assert final_status == "Succeeded"

    # Break exactly one thing: acknowledge the same nonce again after the job has already
    # completed -- the claim window is now closed and the nonce is no longer valid. Real AWS
    # rejects this with ValidationException (NOT InvalidNonceException, which is reserved for a
    # nonce that never matched at all), carrying a message naming the job as already acknowledged.
    code, message = _error_code_and_message(lambda: cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"]))
    assert (code, message) == (
        "ValidationException",
        f"Job with id {job['id']} has already been acknowledged",
    ), (code, message)

    # Effect absent: the rejected post-completion acknowledgement did not revert the action's
    # terminal state.
    status_after = _action_status(ctx, pipeline_name, exec_id, "Source", "SourceAction")
    assert status_after == "Succeeded"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected call to be rejected, but it succeeded")


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


def _create_pipeline_with_retry(ctx, pipeline_name, pipeline, timeout_s=60.0, interval_s=3.0):
    # IAM role/trust propagation is eventually consistent, so CreatePipeline may
    # reject the freshly created role for a few seconds after put_role_policy returns.
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(pipeline=pipeline)
            ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))
            return
        except Exception as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreatePipeline for {pipeline_name} never succeeded: {last_err}")


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
    # CreatePipeline auto-starts exactly one initial execution, and a Custom Source stage
    # only ever advances one execution at a time -- calling StartPipelineExecution ourselves
    # here would queue a SECOND execution that GetPipelineState treats as the newest one,
    # while PollForJobs keeps handing back the auto-started execution's job. Acknowledging
    # and completing that job would then leave the (never-serviced) queued execution's own
    # Source action sitting InProgress forever. So: take whatever job PollForJobs offers,
    # and read the execution id back off the job's own pipelineContext instead of minting one.
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1)
        jobs = resp.get("jobs", [])
        if jobs:
            return jobs[0]
        time.sleep(interval_s)
    raise AssertionError(f"no job appeared for actionTypeId={action_type_id} within {timeout_s}s")


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
