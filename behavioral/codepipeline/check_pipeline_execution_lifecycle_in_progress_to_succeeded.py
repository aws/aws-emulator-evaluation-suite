"""pipeline-execution-lifecycle-in-progress-to-succeeded."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-execution-lifecycle-in-progress-to-succeeded"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartPipelineExecution creates an execution that transitions InProgress ->
    Succeeded, and the transition is observable through both GetPipelineExecution
    and GetPipelineState while it is happening (not just at the end)."""
    cp = ctx.client("codepipeline")
    setup = _setup_ready_pipeline(ctx)
    name = setup["name"]

    resp = cp.start_pipeline_execution(name=name)
    exec_id = resp["pipelineExecutionId"]
    assert exec_id != setup["first_execution_id"], (
        f"StartPipelineExecution returned the drained first execution id {exec_id!r} again"
    )

    status = _get_execution_status_with_retry(ctx, name, exec_id)
    assert status == "InProgress", f"expected InProgress right after start, got {status!r}"

    # Wait until the execution has cleared the Source stage and is parked on the
    # manual Approval action -- this proves it really is mid-flight, not just
    # freshly created.
    token = _wait_for_approval_token(ctx, name)
    state = cp.get_pipeline_state(name=name)
    source_stage = next(s for s in state["stageStates"] if s["stageName"] == _SOURCE_STAGE)
    source_action = next(a for a in source_stage["actionStates"] if a["actionName"] == _SOURCE_ACTION)
    source_status = source_action["latestExecution"]["status"]
    assert source_status == "Succeeded", (
        f"Source stage must have cleared before the run is mid-flight, got {source_status!r}"
    )
    approval_stage = next(s for s in state["stageStates"] if s["stageName"] == _APPROVAL_STAGE)
    approval_action = next(
        a for a in approval_stage["actionStates"] if a["actionName"] == _APPROVAL_ACTION
    )
    approval_status = approval_action["latestExecution"]["status"]
    assert approval_status == "InProgress", (
        f"expected the execution parked on the manual approval, got {approval_status!r}"
    )

    # still InProgress via GetPipelineExecution while waiting on the approval
    mid_status = cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=exec_id)[
        "pipelineExecution"
    ]["status"]
    assert mid_status == "InProgress", (
        f"GetPipelineExecution should agree the run is still InProgress, got {mid_status!r}"
    )

    cp.put_approval_result(
        pipelineName=name,
        stageName=_APPROVAL_STAGE,
        actionName=_APPROVAL_ACTION,
        result={"summary": "approve", "status": "Approved"},
        token=token,
    )
    final_status = _poll_execution_status(ctx, name, exec_id, {"Succeeded", "Failed"})
    assert final_status == "Succeeded", f"expected the approved run to succeed, got {final_status!r}"

    # terminal state persists on re-read
    reread = cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=exec_id)[
        "pipelineExecution"
    ]["status"]
    assert reread == "Succeeded", f"terminal status must persist on re-read, got {reread!r}"


# ===== helpers =====
_SOURCE_STAGE = "Source"
_SOURCE_ACTION = "SourceAction"
_APPROVAL_STAGE = "Approval"
_APPROVAL_ACTION = "ApprovalAction"


def _create_source_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-src-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup() -> None:
        versions = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=b"PK\x05\x06" + b"\x00" * 18)
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    # IAM role/policy propagation to other services is eventually consistent, but a
    # blind sleep can't bound that wait. _wait_for_approval_token already retries the
    # Source stage once if it fails while the role is still propagating, and
    # _create_pipeline retries CreatePipeline itself on ClientError -- those bounded
    # retries are what actually absorb the lag.
    return role_arn


def _pipeline_declaration(
    name: str,
    role_arn: str,
    bucket: str,
    key: str,
    execution_mode: str | None,
    pipeline_type: str | None,
) -> dict[str, Any]:
    decl: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": _SOURCE_STAGE,
                "actions": [
                    {
                        "name": _SOURCE_ACTION,
                        "actionTypeId": {
                            "category": "Source",
                            "owner": "AWS",
                            "provider": "S3",
                            "version": "1",
                        },
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
                "name": _APPROVAL_STAGE,
                "actions": [
                    {
                        "name": _APPROVAL_ACTION,
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                    }
                ],
            },
        ],
    }
    if execution_mode:
        decl["executionMode"] = execution_mode
    if pipeline_type:
        decl["pipelineType"] = pipeline_type
    return decl


def _create_pipeline(
    ctx,
    role_arn: str,
    bucket: str,
    key: str,
    execution_mode: str | None = None,
    pipeline_type: str | None = None,
) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pipe-")
    decl = _pipeline_declaration(name, role_arn, bucket, key, execution_mode, pipeline_type)
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            cp.create_pipeline(pipeline=decl)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("InvalidStructureException", "ValidationException") or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _get_action_state(ctx, pipeline_name: str, stage_name: str, action_name: str) -> dict[str, Any] | None:
    cp = ctx.client("codepipeline")
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state.get("stageStates", []):
        if stage["stageName"] == stage_name:
            for action in stage.get("actionStates", []):
                if action["actionName"] == action_name:
                    return action
    return None


def _wait_for_approval_token(ctx, pipeline_name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    retried_source = False
    while time.monotonic() < deadline:
        action = _get_action_state(ctx, pipeline_name, _APPROVAL_STAGE, _APPROVAL_ACTION)
        if action:
            token = action.get("latestExecution", {}).get("token")
            if token:
                return token
        source_action = _get_action_state(ctx, pipeline_name, _SOURCE_STAGE, _SOURCE_ACTION)
        if source_action and not retried_source:
            if source_action.get("latestExecution", {}).get("status") == "Failed":
                # Transient role-propagation failure on a freshly minted role; retry
                # the Source stage once rather than failing the whole check.
                execs = cp.list_pipeline_executions(pipelineName=pipeline_name)[
                    "pipelineExecutionSummaries"
                ]
                exec_id = execs[0]["pipelineExecutionId"]
                try:
                    cp.retry_stage_execution(
                        pipelineName=pipeline_name,
                        stageName=_SOURCE_STAGE,
                        pipelineExecutionId=exec_id,
                        retryMode="ALL_ACTIONS",
                    )
                    retried_source = True
                except ClientError:
                    pass
        time.sleep(interval_s)
    raise AssertionError(f"approval token for {pipeline_name} never appeared within {timeout_s}s")


def _poll_execution_status(
    ctx, pipeline_name: str, execution_id: str, terminal_statuses: set[str],
    timeout_s: float = 180.0, interval_s: float = 3.0,
) -> str:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        try:
            resp = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                # brief propagation lag right after Start/Rollback/RetryStageExecution
                time.sleep(interval_s)
                continue
            raise
        last = resp["pipelineExecution"]["status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {execution_id} did not reach {terminal_statuses}, last saw {last}")


def _get_execution_status_with_retry(
    ctx, pipeline_name: str, execution_id: str, timeout_s: float = 30.0, interval_s: float = 2.0
) -> str:
    """GetPipelineExecution called immediately after StartPipelineExecution can
    transiently 404 while the execution record propagates; retry briefly."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)
            return resp["pipelineExecution"]["status"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _setup_ready_pipeline(ctx) -> dict[str, str]:
    bucket = _create_source_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    pipeline_name = _create_pipeline(ctx, role_arn, bucket, "source.zip")
    token = _wait_for_approval_token(ctx, pipeline_name)
    cp = ctx.client("codepipeline")
    execs = cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"]
    first_exec_id = execs[0]["pipelineExecutionId"]
    cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName=_APPROVAL_STAGE,
        actionName=_APPROVAL_ACTION,
        result={"summary": "auto-drain initial execution", "status": "Approved"},
        token=token,
    )
    _poll_execution_status(ctx, pipeline_name, first_exec_id, {"Succeeded"})
    return {"name": pipeline_name, "bucket": bucket, "role_arn": role_arn, "first_execution_id": first_exec_id}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
