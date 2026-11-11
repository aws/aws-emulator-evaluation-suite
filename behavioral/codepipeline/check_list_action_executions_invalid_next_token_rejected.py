"""list-action-executions-invalid-next-token-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-action-executions-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]

_SCENARIO = "codepipeline-list-action-executions-invalid-next-token"


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListActionExecutions called with a malformed/expired nextToken fails with
    InvalidNextTokenException rather than silently returning an empty page."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_type_id, _ = _register_source_action_type(ctx, cp)
    pipeline_name = _create_source_and_approve_pipeline(ctx, cp, role_arn, bucket, source_type_id)

    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    job = _poll_for_job(cp, source_type_id)
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    cp.put_job_success_result(jobId=job["id"])

    # positive control: a plain, tokenless call succeeds and returns our source action
    # execution -- poll here (rather than on GetPipelineState) since ListActionExecutions
    # is the very API under test and is what we assert distinct-error behavior against
    details = _poll_action_executions_for(cp, pipeline_name, exec_id, "SourceAction")
    assert any(d["pipelineExecutionId"] == exec_id and d["actionName"] == "SourceAction" for d in details), details

    # negative: a garbage nextToken is rejected outright, not treated as an empty page
    bogus_token = "not-a-real-token-###"
    refusal = _error_code(
        lambda: cp.list_action_executions(pipelineName=pipeline_name, nextToken=bogus_token)
    )
    assert refusal == (
        "InvalidNextTokenException",
        f"The nextToken value '{bogus_token}' is not valid. Specify a valid nextToken value, and then try again.",
    ), refusal


def _error_code(fn):
    """Call fn(); return (code, message) of its refusal. An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_action_executions_for(cp, pipeline_name: str, exec_id: str, action_name: str, timeout_s: float = 90.0) -> list:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            details = cp.list_action_executions(pipelineName=pipeline_name)["actionExecutionDetails"]
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ThrottlingException", "TooManyRequestsException"):
                time.sleep(2.0)
                continue
            raise
        if any(d.get("pipelineExecutionId") == exec_id and d.get("actionName") == action_name for d in details):
            return details
        last = details
        time.sleep(1.5)
    raise AssertionError(f"{action_name} never appeared in ListActionExecutions; last={last}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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


def _register_source_action_type(ctx, cp) -> tuple[dict, str]:
    provider = ctx.unique_name("CustSrc-")[:35]
    cp.create_custom_action_type(
        category="Source",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Source", provider=provider, version="1"))
    return {"category": "Source", "owner": "Custom", "provider": provider, "version": "1"}, provider


def _create_source_and_approve_pipeline(ctx, cp, role_arn: str, bucket: str, source_type_id: dict) -> str:
    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")
    definition = {
        "name": pipeline_name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": source_type_id,
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }],
            },
            {
                "name": "Approve",
                "actions": [{
                    "name": "ApproveAction",
                    "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                }],
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
            cp.create_pipeline(pipeline=definition)
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"create_pipeline never succeeded (role propagation?): {last_err}")


def _poll_for_job(cp, action_type_id: dict, timeout_s: float = 40.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1)
        jobs = resp.get("jobs", [])
        if jobs:
            return jobs[0]
        time.sleep(1.5)
    raise AssertionError("no job appeared for action type within timeout")


def _get_action_state(cp, pipeline_name: str, stage_name: str, action_name: str) -> dict | None:
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state.get("stageStates", []):
        if stage["stageName"] == stage_name:
            for action in stage.get("actionStates", []):
                if action["actionName"] == action_name:
                    return action
    return None


def _poll_action_status(cp, pipeline_name: str, stage_name: str, action_name: str, want_status: str, timeout_s: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            action = _get_action_state(cp, pipeline_name, stage_name, action_name)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ThrottlingException", "TooManyRequestsException"):
                time.sleep(2.0)
                continue
            raise
        if action and action.get("latestExecution", {}).get("status") == want_status:
            return action
        last = action
        time.sleep(1.5)
    raise AssertionError(f"action {action_name} never reached status {want_status}; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
