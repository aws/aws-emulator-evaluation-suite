"""override-stage-condition-conflict-detection."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "override-stage-condition-conflict-detection"
GROUP = "concurrency"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent OverrideStageCondition calls on the same failed condition let at least one win while the losers
    fail with ConditionNotOverridableException, and the override unblocks the stage so its Build job is
    dispatched.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_type_id, _ = _register_action_type(ctx, cp, "Source", 0, 1)
    build_type_id, _ = _register_action_type(ctx, cp, "Build", 1, 0)
    pipeline_name = _create_gated_pipeline(ctx, cp, role_arn, bucket, source_type_id, build_type_id)

    # CreatePipeline auto-starts the pipeline's first execution; ride that one instead of
    # also calling StartPipelineExecution ourselves -- a second, explicitly-started
    # execution queues behind the auto-started one's still-open Source stage and its own
    # Source job never appears, so the beforeEntry condition this check races against
    # would never get evaluated at all. The real exec_id comes off the job CodePipeline
    # actually handed out, not off a call this check makes independently of it.
    source_job = _poll_for_job(cp, source_type_id, exec_id=None)
    exec_id = source_job["data"]["pipelineContext"]["pipelineExecutionId"]
    cp.acknowledge_job(jobId=source_job["id"], nonce=source_job["nonce"])
    _upload_output_artifact(ctx, source_job)
    # deliberately mismatched value -- makes the VariableCheck rule (and hence the
    # beforeEntry condition) fail deterministically, blocking entry to the Build stage
    cp.put_job_success_result(
        jobId=source_job["id"],
        currentRevision={"revision": "rev-1", "changeIdentifier": "rev-1"},
        outputVariables={"RepoName": "actual-repo"},
    )

    _poll_condition_status(cp, pipeline_name, "Build", "Failed")

    # fire concurrent override requests against the same stale, failed condition state
    n_racers = 6
    results: list[tuple[bool, tuple[str, str] | None]] = []
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [
            pool.submit(_try_override, cp, pipeline_name, exec_id)
            for _ in range(n_racers)
        ]
        for f in futures:
            results.append(f.result())

    successes = [r for r in results if r[0]]
    failures = [r for r in results if not r[0]]

    assert len(successes) >= 1, "no concurrent override request ever succeeded"
    assert len(failures) >= 1, "no concurrent override request ever lost the race"
    # AWS names the pipeline (not the execution id) in the "execution" slot of this message.
    expected_refusal = (
        "ConditionNotOverridableException",
        "The condition type BEFORE_ENTRY in stage Build cannot be overridden now. Either it "
        f"contains no failed or in-progress rule, the execution '{pipeline_name}' is already "
        "superseded, or the pipeline definition has changed since the rules(s) failed.",
    )
    for _, refusal in failures:
        assert refusal == expected_refusal, refusal

    # effect: the override that won actually unblocks the stage -- the condition state
    # flips to Overridden and the Build custom action's job becomes pollable
    _poll_condition_status(cp, pipeline_name, "Build", "Overridden")
    build_job = _poll_for_job(cp, build_type_id, exec_id)
    assert build_job["id"], "build action's job never appeared for the execution that was overridden"


def _try_override(cp, pipeline_name: str, exec_id: str) -> tuple[bool, tuple[str, str] | None]:
    try:
        cp.override_stage_condition(
            pipelineName=pipeline_name, stageName="Build", pipelineExecutionId=exec_id, conditionType="BEFORE_ENTRY"
        )
        return True, None
    except ClientError as e:
        err = e.response.get("Error", {})
        return False, (err.get("Code"), err.get("Message"))


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    # us-east-1 is S3's default region and rejects an explicit LocationConstraint for it;
    # the bucket still lands in ctx.region either way, this is not a region pin.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:GetBucketVersioning", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="artifact-access", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="artifact-access"))
    return role_arn


def _register_action_type(ctx, cp, category: str, input_count: int, output_count: int) -> tuple[dict, str]:
    provider = ctx.unique_name(f"Cust{category}-")[:35]
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": input_count, "maximumCount": max(input_count, 1) if input_count else 0},
        outputArtifactDetails={"minimumCount": output_count, "maximumCount": max(output_count, 1) if output_count else 0},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version="1"))
    return {"category": category, "owner": "Custom", "provider": provider, "version": "1"}, provider


def _create_gated_pipeline(ctx, cp, role_arn: str, bucket: str, source_type_id: dict, build_type_id: dict) -> str:
    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")
    definition = {
        "name": pipeline_name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": source_type_id,
                    "outputArtifacts": [{"name": "SourceOutput"}],
                    "namespace": "SourceVars",
                }],
            },
            {
                "name": "Build",
                "actions": [{
                    "name": "BuildAction",
                    "actionTypeId": build_type_id,
                    "inputArtifacts": [{"name": "SourceOutput"}],
                }],
                "beforeEntry": {
                    "conditions": [{
                        "result": "FAIL",
                        "rules": [{
                            "name": "RepoNameCheck",
                            "ruleTypeId": {"category": "Rule", "owner": "AWS", "provider": "VariableCheck", "version": "1"},
                            "configuration": {
                                "Operator": "EQ",
                                "Value": "expected-repo",
                                "Variable": "#{SourceVars.RepoName}",
                            },
                            "region": ctx.region,
                        }],
                    }],
                },
            },
        ],
    }
    _create_pipeline_with_retry(cp, definition)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))
    return pipeline_name


def _create_pipeline_with_retry(cp, definition: dict, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(pipeline=definition, tags=[{"key": "sim2real", "value": CHECK}])
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"create_pipeline never succeeded (role propagation?): {last_err}")


def _poll_for_job(cp, action_type_id: dict, exec_id: str | None, timeout_s: float = 40.0) -> dict:
    """Poll for a job. When `exec_id` is given, only accept one tied to *that*
    pipelineExecutionId -- once a second execution exists, PollForJobs can hand back
    either one's job, and conflating them stalls whichever one gets ignored forever.
    `exec_id=None` is for the very first poll, before any execution's id is known: at
    that point the pipeline's auto-started execution is the only one in flight, so
    whichever job appears first is the one to drive."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10)
        for job in resp.get("jobs", []):
            job_exec_id = job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId")
            if exec_id is None or job_exec_id == exec_id:
                return job
        time.sleep(1.5)
    raise AssertionError(f"no job for execution {exec_id} appeared for action type within timeout")


def _poll_condition_status(cp, pipeline_name: str, stage_name: str, want_status: str, timeout_s: float = 180.0) -> None:
    """GetPipelineState nests the beforeEntry condition's status under
    beforeEntryConditionState.conditionStates[].latestExecution.status -- NOT under a
    top-level beforeEntryConditionState.latestExecution (that key exists in the Smithy
    shape but real AWS leaves it absent; only conditionStates is populated)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            state = cp.get_pipeline_state(name=pipeline_name)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ThrottlingException", "TooManyRequestsException"):
                time.sleep(2.0)
                continue
            raise
        for stage in state.get("stageStates", []):
            if stage["stageName"] == stage_name:
                condition_states = stage.get("beforeEntryConditionState", {}).get("conditionStates", [])
                status = condition_states[0].get("latestExecution", {}).get("status") if condition_states else None
                if status == want_status:
                    return
                last = status
        time.sleep(1.5)
    raise AssertionError(f"beforeEntry condition on {stage_name} never reached {want_status}; last={last}")


def _upload_output_artifact(ctx, job: dict) -> None:
    out_artifacts = job.get("data", {}).get("outputArtifacts", [])
    if not out_artifacts:
        return
    creds = job["data"]["artifactCredentials"]
    s3 = ctx.client(
        "s3",
        creds={
            "aws_access_key_id": creds["accessKeyId"],
            "aws_secret_access_key": creds["secretAccessKey"],
            "aws_session_token": creds["sessionToken"],
        },
    )
    loc = out_artifacts[0]["location"]["s3Location"]
    s3.put_object(Bucket=loc["bucketName"], Key=loc["objectKey"], Body=b"PK\x05\x06" + b"\x00" * 18)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
