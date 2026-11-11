"""put-job-success-result-wrong-job-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-job-success-result-wrong-job-state-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]

_SOURCE_STAGE = "Source"
_SOURCE_ACTION = "SourceAction"
_BUILD_STAGE = "Build"
_BUILD_ACTION = "BuildAction"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutJobSuccessResult on a job already in the terminal Failed state fails with
    InvalidJobStateException and leaves it Failed; repeating it on a Succeeded job is a no-op."""
    cp = ctx.client("codepipeline")
    bucket = _create_source_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    provider = _create_custom_build_type(ctx)
    pipeline = _create_pipeline(ctx, role_arn, bucket, "source.zip", provider)

    # exec1: drive the job to a terminal Failed state, then try to flip it to Succeeded
    exec1 = _wait_for_execution(ctx, pipeline)
    job1 = _run_build_job(ctx, provider, exec1)
    cp.put_job_failure_result(jobId=job1, failureDetails={"type": "JobFailed", "message": "seed failure"})
    status1 = _wait_action_status(ctx, pipeline, exec1, {"Failed"}, action_name=_BUILD_ACTION)
    assert status1 == "Failed"

    error = _error(lambda: cp.put_job_success_result(jobId=job1))
    assert error.get("Code") == "InvalidJobStateException", f"expected InvalidJobStateException, got {error!r}"
    expected_message = f"Job with id {job1} has already terminated"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # effect absent: the rejected success call did not flip the terminal Failed state
    still = _wait_action_status(ctx, pipeline, exec1, {"Failed"}, action_name=_BUILD_ACTION)
    assert still == "Failed"

    # exec2: a genuinely InProgress job succeeds normally, and repeating the exact same
    # success call on it afterwards is a real, observed no-op (idempotent), not an error
    exec2 = cp.start_pipeline_execution(name=pipeline)["pipelineExecutionId"]
    job2 = _run_build_job(ctx, provider, exec2)
    cp.put_job_success_result(jobId=job2)
    final = _wait_action_status(ctx, pipeline, exec2, {"Succeeded"}, action_name=_BUILD_ACTION)
    assert final == "Succeeded"
    cp.put_job_success_result(jobId=job2)  # idempotent repeat: does not raise
    still2 = _wait_action_status(ctx, pipeline, exec2, {"Succeeded"}, action_name=_BUILD_ACTION)
    assert still2 == "Succeeded"





def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_source_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-src-").lower().replace("_", "-")
    # S3 CreateBucket API quirk, not a hardcoded target region: us-east-1 rejects an explicit
    # LocationConstraint, every other region requires one. The bucket still lands in ctx.region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup() -> None:
        versions = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="source.zip", Body=b"PK\x05\x06" + b"\x00" * 18)
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    _wait_for_role_policy_visible(iam, role_name, "s3-access")
    return role_arn


def _wait_for_role_policy_visible(iam, role_name: str, policy_name: str, timeout_s: float = 30.0) -> None:
    """Bounded poll for the inline policy read to reach IAM's own eventually-consistent
    replicas -- CodePipeline's own CreatePipeline retry loop absorbs any residual
    cross-service propagation delay beyond that."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        if policy_name in names:
            return
        time.sleep(2)
    raise AssertionError(f"inline policy {policy_name!r} on role {role_name!r} never became visible")


def _create_custom_build_type(ctx) -> str:
    # PollForJobs / job-dispatch is only supported for custom Build, Deploy, Test, and Invoke
    # actions -- NOT custom Source actions, which the CodePipeline job-worker model does not
    # support (see "Create and add a custom action" in the user guide).
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("cpbld-")[:25]
    cp.create_custom_action_type(
        category="Build",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Build", provider=provider, version="1"))
    return provider


def _create_pipeline(ctx, role_arn: str, bucket: str, key: str, provider: str) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pipe-")
    decl = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": _SOURCE_STAGE,
                "actions": [
                    {
                        "name": _SOURCE_ACTION,
                        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                        "configuration": {
                            "S3Bucket": bucket,
                            "S3ObjectKey": key,
                            "PollForSourceChanges": "false",
                        },
                        "outputArtifacts": [{"name": "SourceOutput"}],
                    }
                ],
            },
            {
                "name": _BUILD_STAGE,
                "actions": [
                    {
                        "name": _BUILD_ACTION,
                        "actionTypeId": {
                            "category": "Build",
                            "owner": "Custom",
                            "provider": provider,
                            "version": "1",
                        },
                    }
                ],
            },
        ],
    }
    pipeline_tags = [{"key": "sim2real-check", "value": CHECK}]
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            cp.create_pipeline(pipeline=decl, tags=pipeline_tags)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("InvalidStructureException", "ValidationException") or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _wait_for_execution(ctx, pipeline_name, timeout_s=120) -> str:
    """The pipeline auto-starts its first execution on creation; return its id."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs:
            return execs[0]["pipelineExecutionId"]
        time.sleep(2)
    raise AssertionError(f"no execution ever appeared for {pipeline_name}")


def _run_build_job(ctx, provider, exec_id, timeout_s=180) -> str:
    """Poll for the Build job belonging to exec_id and acknowledge it (Queued -> InProgress)."""
    cp = ctx.client("codepipeline")
    action_type_id = {"category": "Build", "owner": "Custom", "provider": provider, "version": "1"}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10).get("jobs", [])
        for j in jobs:
            if j["data"]["pipelineContext"]["pipelineExecutionId"] == exec_id:
                cp.acknowledge_job(jobId=j["id"], nonce=j["nonce"])
                return j["id"]
        time.sleep(2)
    raise AssertionError(f"no build job appeared for execution {exec_id} within {timeout_s}s")


def _wait_action_status(ctx, pipeline_name, exec_id, statuses, action_name, timeout_s=90) -> str:
    """Poll a specific action's status for a specific execution via ListActionExecutions."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        details = cp.list_action_executions(
            pipelineName=pipeline_name, filter={"pipelineExecutionId": exec_id}
        ).get("actionExecutionDetails", [])
        for d in details:
            if d.get("actionName") == action_name:
                last = d.get("status")
        if last in statuses:
            return last
        time.sleep(2)
    raise AssertionError(f"action {action_name} for execution {exec_id} never reached {statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

