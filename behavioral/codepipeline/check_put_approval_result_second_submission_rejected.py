"""put-approval-result-second-submission-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-approval-result-second-submission-rejected"
GROUP = "concurrency"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second PutApprovalResult against an already-resolved approval action
    is rejected with ApprovalAlreadyCompletedException, and the action's
    outcome from the first (winning) submission is preserved unchanged."""
    role_arn = _iam_role_arn(ctx)
    artifact_bucket = _artifact_bucket(ctx)
    source_bucket = _source_bucket(ctx)
    name = ctx.unique_name("sim2real-cp-appr-")
    _create_pipeline(
        ctx,
        name,
        role_arn,
        artifact_bucket,
        source_bucket,
        stage2_actions=[
            {
                "name": "ApprovalAction",
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                "runOrder": 1,
            }
        ],
    )

    cp = ctx.client("codepipeline")
    cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    approval = _wait_for_action_state(ctx, name, "Approve", "ApprovalAction", {"InProgress"})
    token = approval["token"]

    # positive control: the first submission resolves the approval
    first = _put_approval_result(ctx, name, "Approve", "ApprovalAction", token, "Approved")
    assert "approvedAt" in first, f"positive control did not resolve the approval: {first}"
    _wait_for_action_state(ctx, name, "Approve", "ApprovalAction", {"Succeeded"})

    # negative: a second submission against the same (now stale) token is rejected
    error = _error(
        lambda: _put_approval_result(ctx, name, "Approve", "ApprovalAction", token, "Rejected")
    )
    assert error.get("Code") == "ApprovalAlreadyCompletedException", error
    expected_message = (
        "The approval request that you responded to is already complete or has expired. "
        "Review the latest revisions in the pipeline, and then try again."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # effect absent: the action's outcome from the winning first submission was not overturned
    final_state = _wait_for_action_state(ctx, name, "Approve", "ApprovalAction", {"Succeeded", "Failed"})
    assert final_state["status"] == "Succeeded", final_state


# ===== helpers =====

def _error(fn: Any) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _iam_role_arn(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "put-approval-result-second-submission-rejected"}],
    )["Role"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-cp-inline",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cp-inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _artifact_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-artifacts-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "put-approval-result-second-submission-rejected"}]},
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _source_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-source-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "put-approval-result-second-submission-rejected"}]},
    )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=name, Key="source.zip", Body=b"PK\x05\x06" + b"\x00" * 18)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        versions = s3.list_object_versions(Bucket=name)
        delete_list = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        delete_list += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])]
        if delete_list:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": delete_list}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_pipeline(
    ctx: Any,
    name: str,
    role_arn: str,
    artifact_bucket: str,
    source_bucket: str,
    stage2_actions: list[dict[str, Any]],
    execution_mode: str | None = None,
    pipeline_type: str | None = None,
    stage2_before_entry: dict[str, Any] | None = None,
    source_namespace: str | None = None,
) -> dict[str, Any]:
    cp = ctx.client("codepipeline")
    source_action: dict[str, Any] = {
        "name": "SourceAction",
        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
        "configuration": {"S3Bucket": source_bucket, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"},
        "outputArtifacts": [{"name": "SourceOutput"}],
        "runOrder": 1,
    }
    if source_namespace:
        source_action["namespace"] = source_namespace
    stage2: dict[str, Any] = {"name": "Approve", "actions": stage2_actions}
    if stage2_before_entry:
        stage2["beforeEntry"] = stage2_before_entry
    pipeline_def: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [{"name": "Source", "actions": [source_action]}, stage2],
    }
    if execution_mode:
        pipeline_def["executionMode"] = execution_mode
    if pipeline_type:
        pipeline_def["pipelineType"] = pipeline_type

    resp = None
    last_err: Exception | None = None
    for attempt in range(10):
        try:
            resp = cp.create_pipeline(
                pipeline=pipeline_def,
                tags=[{"key": "sim2real", "value": "put-approval-result-second-submission-rejected"}],
            )
            break
        except ClientError as e:
            last_err = e
            if attempt < 9:
                time.sleep(3)
                continue
            raise
    assert resp is not None, str(last_err)
    ctx.on_cleanup(lambda: _delete_pipeline_quiet(ctx, name))
    return resp["pipeline"]


def _delete_pipeline_quiet(ctx: Any, name: str) -> None:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.delete_pipeline(name=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "PipelineNotFoundException":
                return
            if code != "ConcurrentModificationException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _wait_for_action_state(
    ctx: Any, pipeline_name: str, stage_name: str, action_name: str, target_statuses: set[str], timeout_s: float = 120
) -> dict[str, Any]:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        state = cp.get_pipeline_state(name=pipeline_name)
        for stage in state.get("stageStates", []):
            if stage["stageName"] == stage_name:
                for action in stage.get("actionStates", []):
                    if action["actionName"] == action_name:
                        latest = action.get("latestExecution", {})
                        last_status = latest.get("status")
                        if last_status in target_statuses:
                            return latest
        time.sleep(3)
    raise AssertionError(
        f"action {action_name} in stage {stage_name} never reached {target_statuses}, last={last_status}"
    )


def _put_approval_result(
    ctx: Any, pipeline_name: str, stage_name: str, action_name: str, token: str, status: str, summary: str = "sim2real"
) -> dict[str, Any]:
    cp = ctx.client("codepipeline")
    return cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName=stage_name,
        actionName=action_name,
        result={"summary": summary, "status": status},
        token=token,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
