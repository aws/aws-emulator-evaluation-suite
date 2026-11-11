"""put-approval-result-invalid-token-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-approval-result-invalid-token-rejected"
GROUP = "server-side"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutApprovalResult with a stale/incorrect token is rejected and does not resolve the approval; the real token still works."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)

    source_provider = ctx.unique_name("sim2real-cp-src-")
    _create_custom_action_type(ctx, "Source", source_provider, "1", 0, 0, 1, 1, tags=[{"key": "sim2real-check", "value": CHECK}])

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
                "name": "Approve",
                "actions": [{
                    "name": "ApproveAction",
                    "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                    "configuration": {},
                }],
            },
        ],
    }
    _create_pipeline_with_retry(cp, pipeline, tags=[{"key": "sim2real-check", "value": CHECK}])
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    cp.start_pipeline_execution(name=pipeline_name)

    source_job = _poll_one_job(
        ctx, {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"}
    )
    _ack_and_succeed(ctx, source_job)

    real_token = _poll_for_approval_token(ctx, pipeline_name, "Approve", "ApproveAction", timeout_s=60.0)
    bogus_token = str(uuid.uuid4())
    assert bogus_token != real_token, f"forged token {bogus_token!r} collided with real token {real_token!r}"

    error = _error(lambda: cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName="Approve",
        actionName="ApproveAction",
        result={"summary": "forged rejection", "status": "Rejected"},
        token=bogus_token,
    ))
    assert error.get("Code") == "InvalidApprovalTokenException", f"expected InvalidApprovalTokenException, got {error!r}"
    # AWS wraps the token in typographic quotes (U+2018 / U+2019).
    expected_message = (
        f"Approval token \u2018{bogus_token}\u2019 either does not exist or is not the correct token "
        "for action ApproveAction and stage Approve."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent: the approval action is still awaiting response with the same token.
    token_after_rejection = _poll_for_approval_token(ctx, pipeline_name, "Approve", "ApproveAction", timeout_s=30.0)
    assert token_after_rejection == real_token, "the bogus token attempt disturbed the outstanding approval"

    # Positive control: the real token is accepted.
    resp = cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName="Approve",
        actionName="ApproveAction",
        result={"summary": "looks good", "status": "Approved"},
        token=real_token,
    )
    assert "approvedAt" in resp, f"expected approvedAt in response, got {resp!r}"

    final_status = _poll_until_action_status(ctx, pipeline_name, "Approve", "ApproveAction", "Succeeded")
    assert final_status == "Succeeded", f"expected Succeeded, got {final_status!r}"


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _create_pipeline_with_retry(cp, pipeline: dict, tags=None, timeout_s: float = 60.0, interval_s: float = 5.0) -> None:
    """CodePipeline validates roleArn by attempting to assume it; a freshly created role/trust
    policy can lag IAM's eventual consistency, so retry on rejection until the deadline instead of
    guessing a fixed propagation delay."""
    kwargs = {"pipeline": pipeline}
    if tags:
        kwargs["tags"] = tags
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(**kwargs)
            return
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"create_pipeline never succeeded within {timeout_s}s; last error: {last_err}")


def _create_custom_action_type(ctx, category, provider, version, in_min, in_max, out_min, out_max, config_props=None, tags=None):
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
    if tags:
        kwargs["tags"] = tags
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


def _find_action_state(ctx, pipeline_name, stage_name, action_name):
    cp = ctx.client("codepipeline")
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state.get("stageStates", []):
        if stage["stageName"] != stage_name:
            continue
        for action in stage.get("actionStates", []):
            if action["actionName"] == action_name:
                return action
    return None


def _poll_for_approval_token(ctx, pipeline_name, stage_name, action_name, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        action = _find_action_state(ctx, pipeline_name, stage_name, action_name)
        if action:
            latest = action.get("latestExecution", {})
            token = latest.get("token")
            if token:
                return token
        time.sleep(interval_s)
    raise AssertionError(f"approval token for {stage_name}/{action_name} never appeared within {timeout_s}s")


def _poll_until_action_status(ctx, pipeline_name, stage_name, action_name, target, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        action = _find_action_state(ctx, pipeline_name, stage_name, action_name)
        if action:
            status = action.get("latestExecution", {}).get("status")
            if status == target:
                return status
        time.sleep(interval_s)
    raise AssertionError(f"action {stage_name}/{action_name} never reached {target}, last seen {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
