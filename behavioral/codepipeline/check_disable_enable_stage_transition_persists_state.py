"""disable-enable-stage-transition-persists-state."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-enable-stage-transition-persists-state"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DisableStageTransition blocks the inbound transition for a stage and
    EnableStageTransition reverses it, both durably reflected in GetPipelineState
    (not just in the immediate API response)."""
    cp = ctx.client("codepipeline")
    setup = _setup_ready_pipeline(ctx)
    name = setup["name"]
    reach_approval_s = setup["reach_approval_s"]

    cp.disable_stage_transition(
        pipelineName=name,
        stageName=_APPROVAL_STAGE,
        transitionType="Inbound",
        reason="sim2real behavioral check disable",
    )
    state = cp.get_pipeline_state(name=name)
    approval_stage = next(s for s in state["stageStates"] if s["stageName"] == _APPROVAL_STAGE)
    assert approval_stage["inboundTransitionState"]["enabled"] is False, (
        f"expected inboundTransitionState.enabled False right after DisableStageTransition, "
        f"got {approval_stage['inboundTransitionState']!r}"
    )
    assert approval_stage["inboundTransitionState"]["disabledReason"] == "sim2real behavioral check disable", (
        f"disabledReason must round-trip the supplied reason via an independent GetPipelineState read, "
        f"got {approval_stage['inboundTransitionState'].get('disabledReason')!r}"
    )

    # while disabled, a new execution cannot flow into the blocked stage: it should
    # start (Source succeeds) but stall before ever reaching the Approval action. The
    # setup execution just measured how long this account/pipeline normally takes to
    # reach Approval (reach_approval_s); holding the window to >=3x that means a
    # correct-but-slower target cannot be mistaken for a blocked one.
    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    hold_window_s = max(15.0, 3.0 * reach_approval_s)
    deadline = time.monotonic() + hold_window_s
    saw_token = False
    while time.monotonic() < deadline:
        action = _get_action_state(ctx, name, _APPROVAL_STAGE, _APPROVAL_ACTION)
        if action and action.get("latestExecution", {}).get("token"):
            saw_token = True
            break
        time.sleep(3)
    assert not saw_token, (
        f"approval action should not have started while inbound transition is disabled "
        f"(waited {hold_window_s:.1f}s, >= 3x the {reach_approval_s:.1f}s the setup execution "
        f"took to reach Approval)"
    )
    status_while_blocked = cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=exec_id)[
        "pipelineExecution"
    ]["status"]
    assert status_while_blocked == "InProgress", (
        f"execution {exec_id} must remain InProgress while held at the disabled Approval "
        f"transition, got {status_while_blocked!r}"
    )

    cp.enable_stage_transition(pipelineName=name, stageName=_APPROVAL_STAGE, transitionType="Inbound")
    state2 = cp.get_pipeline_state(name=name)
    approval_stage2 = next(s for s in state2["stageStates"] if s["stageName"] == _APPROVAL_STAGE)
    assert approval_stage2["inboundTransitionState"]["enabled"] is True, (
        f"expected inboundTransitionState.enabled True via an independent GetPipelineState read "
        f"after EnableStageTransition, got {approval_stage2['inboundTransitionState']!r}"
    )

    # now that the transition is re-enabled, the stalled execution proceeds
    token = _wait_for_approval_token(ctx, name)
    cp.put_approval_result(
        pipelineName=name, stageName=_APPROVAL_STAGE, actionName=_APPROVAL_ACTION,
        result={"summary": "unblocked", "status": "Approved"}, token=token,
    )
    final_status = _poll_execution_status(ctx, name, exec_id, {"Succeeded", "Failed"})
    assert final_status == "Succeeded", (
        f"execution {exec_id} must reach Succeeded once re-enabled and approved, got {final_status!r}"
    )


_SOURCE_STAGE = "Source"
_SOURCE_ACTION = "SourceAction"
_APPROVAL_STAGE = "Approval"
_APPROVAL_ACTION = "ApprovalAction"


def _create_source_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-src-")
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for;
    # this is not pinning the check to a region, it follows ctx.region either way.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
    return role_arn


def _pipeline_declaration(
    name: str, role_arn: str, bucket: str, key: str,
    execution_mode: str | None, pipeline_type: str | None,
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
                            "category": "Source", "owner": "AWS", "provider": "S3", "version": "1",
                        },
                        "configuration": {
                            "S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false",
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
                            "category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1",
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
    ctx, role_arn: str, bucket: str, key: str,
    execution_mode: str | None = None, pipeline_type: str | None = None,
) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pipe-")
    decl = _pipeline_declaration(name, role_arn, bucket, key, execution_mode, pipeline_type)
    tags = [{"key": "sim2real", "value": CHECK}]
    # IAM role creation is eventually consistent: CreatePipeline can reject the fresh
    # role's AssumeRole for a short window. Retry only that specific, named transient
    # error with a bounded deadline -- anything else is a real failure and must raise.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=decl, tags=tags)
            break
        except ClientError as e:
            err = e.response.get("Error", {})
            transient = err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get("Message", "")
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)
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
                execs = cp.list_pipeline_executions(pipelineName=pipeline_name)[
                    "pipelineExecutionSummaries"
                ]
                exec_id = execs[0]["pipelineExecutionId"]
                try:
                    cp.retry_stage_execution(
                        pipelineName=pipeline_name, stageName=_SOURCE_STAGE,
                        pipelineExecutionId=exec_id, retryMode="ALL_ACTIONS",
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
        resp = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)
        last = resp["pipelineExecution"]["status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {execution_id} did not reach {terminal_statuses}, last saw {last}")


def _setup_ready_pipeline(ctx) -> dict[str, Any]:
    bucket = _create_source_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    pipeline_name = _create_pipeline(ctx, role_arn, bucket, "source.zip")
    reach_started = time.monotonic()
    token = _wait_for_approval_token(ctx, pipeline_name)
    reach_approval_s = time.monotonic() - reach_started
    cp = ctx.client("codepipeline")
    execs = cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"]
    first_exec_id = execs[0]["pipelineExecutionId"]
    cp.put_approval_result(
        pipelineName=pipeline_name, stageName=_APPROVAL_STAGE, actionName=_APPROVAL_ACTION,
        result={"summary": "auto-drain initial execution", "status": "Approved"}, token=token,
    )
    _poll_execution_status(ctx, pipeline_name, first_exec_id, {"Succeeded"})
    return {
        "name": pipeline_name, "bucket": bucket, "role_arn": role_arn,
        "first_execution_id": first_exec_id, "reach_approval_s": reach_approval_s,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
