"""list-action-executions-order-matches-stage-sequence."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-action-executions-order-matches-stage-sequence"
GROUP = "ordering"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListActionExecutions returns records in execution order (Source, runOrder=1, runOrder=2);
    action names are chosen so alphabetical order would differ."""
    role_arn = _iam_role_arn(ctx)
    artifact_bucket = _artifact_bucket(ctx)
    source_bucket = _source_bucket(ctx)
    name = ctx.unique_name("sim2real-cp-actord-")
    _create_pipeline(
        ctx,
        name,
        role_arn,
        artifact_bucket,
        source_bucket,
        stage2_actions=[
            {
                "name": "ZebraApprove",
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                "runOrder": 1,
            },
            {
                "name": "AlphaApprove",
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                "runOrder": 2,
            },
        ],
    )

    cp = ctx.client("codepipeline")
    exec_id = _settle_and_start(ctx, name)

    _wait_for_action_state(ctx, name, "Source", "SourceAction", {"Succeeded"})

    zebra = _wait_for_action_state(ctx, name, "Approve", "ZebraApprove", {"InProgress"})
    _put_approval_result(ctx, name, "Approve", "ZebraApprove", zebra["token"], "Approved")

    alpha = _wait_for_action_state(ctx, name, "Approve", "AlphaApprove", {"InProgress"})
    _put_approval_result(ctx, name, "Approve", "AlphaApprove", alpha["token"], "Approved")

    # Action-level status is fast/responsive; the pipeline execution's own aggregate status
    # can lag well behind actual completion, so confirm completion via the action itself.
    _wait_for_action_state(ctx, name, "Approve", "AlphaApprove", {"Succeeded", "Failed"})

    # ListActionExecutions can lag action-level completion by minutes, so poll generously.
    deadline = time.monotonic() + 180
    details: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        resp = cp.list_action_executions(pipelineName=name, filter={"pipelineExecutionId": exec_id})
        details = resp["actionExecutionDetails"]
        if len(details) == 3:
            break
        time.sleep(3)
    assert len(details) == 3, f"expected 3 action executions after polling, got {details}"

    names_returned = [d["actionName"] for d in details]
    start_times = [d["startTime"] for d in details]

    ascending = all(start_times[i] <= start_times[i + 1] for i in range(len(start_times) - 1))
    descending = all(start_times[i] >= start_times[i + 1] for i in range(len(start_times) - 1))
    assert ascending or descending, (
        f"action execution order is not chronologically monotonic: {names_returned} {start_times}"
    )

    alphabetical_asc = sorted(names_returned)
    alphabetical_desc = sorted(names_returned, reverse=True)
    assert names_returned not in (alphabetical_asc, alphabetical_desc), (
        f"action executions appear alphabetized rather than execution-ordered: {names_returned}"
    )

    expected_chronological = ["SourceAction", "ZebraApprove", "AlphaApprove"]
    if ascending:
        assert names_returned == expected_chronological, names_returned
    else:
        assert names_returned == list(reversed(expected_chronological)), names_returned



def _iam_role_arn(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
        # us-east-1 is S3's own historical default region and rejects an explicit
        # LocationConstraint for it; every other region requires one.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _source_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-source-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's own historical default region and rejects an explicit
        # LocationConstraint for it; every other region requires one.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
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
            resp = cp.create_pipeline(pipeline=pipeline_def)
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


def _settle_and_start(ctx: Any, pipeline_name: str, stage_name: str = "Approve") -> str:
    """Start an execution behind a disabled inbound transition to supersede the auto-started one.

    Otherwise approvals could land on the auto-started execution instead of ours."""
    cp = ctx.client("codepipeline")
    cp.disable_stage_transition(
        pipelineName=pipeline_name,
        stageName=stage_name,
        transitionType="Inbound",
        reason="sim2real settling the CreatePipeline auto-triggered execution",
    )
    try:
        exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
        # Wait briefly for the auto-started execution to be listed before reopening the gate;
        # if none appears, there is nothing to settle and we proceed at the deadline.
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            executions = cp.list_pipeline_executions(pipelineName=pipeline_name).get(
                "pipelineExecutionSummaries", []
            )
            if len(executions) >= 2:
                break
            time.sleep(1.0)
    finally:
        cp.enable_stage_transition(pipelineName=pipeline_name, stageName=stage_name, transitionType="Inbound")
    return exec_id


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


def _wait_for_execution_status(
    ctx: Any,
    pipeline_name: str,
    execution_id: str,
    target_statuses: set[str],
    timeout_s: float = 120,
    stage_name: str = "Approve",
) -> str:
    """Wait for target_statuses via stage-level latestExecution status.

    GetPipelineExecution's aggregate status can lag stage completion by several minutes."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        state = cp.get_pipeline_state(name=pipeline_name)
        for stage in state.get("stageStates", []):
            if stage["stageName"] == stage_name:
                latest = stage.get("latestExecution", {})
                if latest.get("pipelineExecutionId") == execution_id:
                    last_status = latest.get("status")
                    if last_status in target_statuses:
                        return last_status
        time.sleep(3)
    raise AssertionError(
        f"execution {execution_id} never reached {target_statuses} (stage={stage_name}), last={last_status}"
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
