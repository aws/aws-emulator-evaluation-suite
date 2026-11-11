"""approval-already-completed-optimistic-lock."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "approval-already-completed-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a resolved approval's token in PutApprovalResult fails with
    ApprovalAlreadyCompletedException and leaves the recorded approval and the
    execution's progress unchanged (single-writer semantics)."""
    cp = ctx.client("codepipeline")

    role_arn = _create_service_role(ctx)
    artifact_bucket = _create_bucket(ctx)
    source_bucket = _create_bucket(ctx, versioned=True)
    source_key = "src/app.zip"
    _put_zip_object(ctx, source_bucket, source_key, "app.txt", b"approval-payload")

    name = ctx.unique_name("sim2real-cp-approval-")
    pipeline_decl = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [
            _source_stage(source_bucket, source_key),
            _approval_stage(),
        ],
    }
    _create_pipeline_with_retry(cp, pipeline_decl)
    ctx.on_cleanup(lambda: _delete_pipeline(cp, name))

    start_resp = _start_execution_with_backoff(cp, name)
    execution_id = start_resp["pipelineExecutionId"]

    token = _poll_until(
        lambda: _approval_token(cp, name, "Approval", "Approve"),
        lambda t: t is not None,
        timeout_s=90.0,
        interval_s=2.0,
    )

    first_result = cp.put_approval_result(
        pipelineName=name,
        stageName="Approval",
        actionName="Approve",
        result={"summary": "first-approval", "status": "Approved"},
        token=token,
    )
    assert "approvedAt" in first_result, f"first PutApprovalResult missing approvedAt: {first_result}"

    resolved_state_1 = _action_state(cp, name, "Approval", "Approve")
    assert resolved_state_1["status"] == "Succeeded", (
        f"expected Succeeded after the winning approval, got {resolved_state_1['status']}"
    )
    first_change_time = resolved_state_1["lastStatusChange"]

    code, message = _error(
        lambda: cp.put_approval_result(
            pipelineName=name,
            stageName="Approval",
            actionName="Approve",
            result={"summary": "duplicate-approval", "status": "Approved"},
            token=token,
        )
    )
    assert code == "ApprovalAlreadyCompletedException", (
        f"expected ApprovalAlreadyCompletedException reusing a resolved token, got {code!r}"
    )
    assert message == (
        "The approval request that you responded to is already complete or has expired. "
        "Review the latest revisions in the pipeline, and then try again."
    ), f"unexpected message: {message!r}"

    resolved_state_2 = _action_state(cp, name, "Approval", "Approve")
    assert resolved_state_2["status"] == "Succeeded", (
        f"expected Succeeded to persist after the rejected duplicate, got {resolved_state_2['status']}"
    )
    assert resolved_state_2["lastStatusChange"] == first_change_time, (
        "the rejected duplicate approval must not change the action's recorded state"
    )

    # Single-writer semantics confirmed above. As a light sanity check (not
    # this check's core assertion -- Manual Approval pipelines can take a
    # while to fully close out the overall pipeline execution in real AWS),
    # confirm the rejected duplicate did not regress the execution into a
    # failed/stopped state; it must still be progressing normally or already
    # done.
    exec_status_after = cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id
    )["pipelineExecution"]["status"]
    assert exec_status_after in ("InProgress", "Succeeded"), exec_status_after


# ===== helpers =====


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_pipeline(cp, name):
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _create_pipeline_with_retry(cp, pipeline: dict, timeout_s: float = 30.0) -> dict:
    """CreatePipeline can transiently fail with InvalidStructureException while the
    freshly created service role is still propagating through IAM. IAM exposes no
    condition to poll for, so retry the exact call to a bounded deadline; expiry
    fails the check."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cp.create_pipeline(pipeline=pipeline)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                last_err = e
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"create_pipeline never succeeded (role propagation?): {last_err}")


def _start_execution_with_backoff(cp, name: str, attempts: int = 5):
    """StartPipelineExecution can be throttled right after a pipeline is
    created/updated in a busy account; retry with explicit backoff beyond
    botocore's default retry budget instead of letting ThrottlingException
    propagate."""
    last_err = None
    for i in range(attempts):
        try:
            return cp.start_pipeline_execution(name=name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException"):
                last_err = e
                time.sleep(1.5 * (i + 1))
                continue
            raise
    raise AssertionError(f"start_pipeline_execution kept throttling: {last_err}")


def _source_stage(source_bucket: str, source_key: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {
                    "category": "Source",
                    "owner": "AWS",
                    "provider": "S3",
                    "version": "1",
                },
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {
                    "S3Bucket": source_bucket,
                    "S3ObjectKey": source_key,
                    "PollForSourceChanges": "false",
                },
            }
        ],
    }


def _approval_stage() -> dict:
    return {
        "name": "Approval",
        "actions": [
            {
                "name": "Approve",
                "actionTypeId": {
                    "category": "Approval",
                    "owner": "AWS",
                    "provider": "Manual",
                    "version": "1",
                },
            }
        ],
    }


def _stage_state(state: dict, stage_name: str) -> dict:
    for s in state["stageStates"]:
        if s["stageName"] == stage_name:
            return s
    raise AssertionError(f"stage {stage_name} not found in pipeline state")


def _action_state(cp, pipeline_name: str, stage_name: str, action_name: str) -> dict:
    state = cp.get_pipeline_state(name=pipeline_name)
    stage = _stage_state(state, stage_name)
    for action in stage.get("actionStates", []):
        if action["actionName"] == action_name:
            return action.get("latestExecution", {})
    raise AssertionError(f"action {action_name} not found in stage {stage_name}")


def _approval_token(cp, name: str, stage_name: str, action_name: str):
    state = cp.get_pipeline_state(name=name)
    stage = _stage_state(state, stage_name)
    for action in stage.get("actionStates", []):
        if action["actionName"] == action_name:
            return action.get("latestExecution", {}).get("token")
    return None


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _zip_bytes(filename: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def _put_zip_object(ctx, bucket: str, key: str, filename: str, content: bytes) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=_zip_bytes(filename, content))


def _create_bucket(ctx, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint of "us-east-1" itself;
        # this branches on the S3 API quirk, not a hardcoded target region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    if versioned:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        try:
            _empty_bucket(ctx, bucket)
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _create_service_role(ctx, extra_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    statements = [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]
    if extra_statements:
        statements.extend(extra_statements)
    policy = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
