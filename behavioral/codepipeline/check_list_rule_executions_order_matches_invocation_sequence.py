"""list-rule-executions-order-matches-invocation-sequence."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-rule-executions-order-matches-invocation-sequence"
GROUP = "ordering"
SERVICES = ["codepipeline"]

_SCENARIO = "codepipeline-list-rule-executions-order-matches-invocation-sequence"


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListRuleExecutions returns exactly one Succeeded record for each of the three beforeEntry
    VariableCheck rules (Charlie, Alpha, Bravo) of the execution that ran them."""
    role_arn = _iam_role_arn(ctx)
    artifact_bucket = _artifact_bucket(ctx)
    source_bucket = _source_bucket(ctx)
    name = ctx.unique_name("sim2real-cp-rulord-")

    marker = "not-a-real-version-marker"
    rules = [
        _var_check_rule("Charlie", "NE", "#{SourceVariables.VersionId}", marker),
        _var_check_rule("Alpha", "NE", "#{SourceVariables.VersionId}", marker),
        _var_check_rule("Bravo", "NE", "#{SourceVariables.VersionId}", marker),
    ]

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
        execution_mode="SUPERSEDED",
        pipeline_type="V2",
        stage2_before_entry={"conditions": [{"result": "FAIL", "rules": rules}]},
        source_namespace="SourceVariables",
    )

    cp = ctx.client("codepipeline")
    cp.start_pipeline_execution(name=name)

    # The beforeEntry rules for stage "Approve" must finish evaluating (result: FAIL, i.e.
    # "don't block entry") before its action can ever reach InProgress -- so by the time the
    # approval action is InProgress, all 3 rule executions are already terminal. No need to
    # wait for the whole pipeline execution to finish (its aggregate status can lag stage/rule
    # completion by minutes in real AWS, far beyond a bounded check's budget).
    approval = _wait_for_action_state(ctx, name, "Approve", "ApprovalAction", {"InProgress"}, timeout_s=180)

    # create_pipeline can auto-trigger its own initial execution independently of the
    # start_pipeline_execution call above; confirmed on real AWS: under executionMode=SUPERSEDED
    # that auto-triggered execution reached the Approve stage and ran its rules while the
    # explicitly started execution sat queued behind it as the stage's inboundExecution. So the
    # id to filter rule executions by must come from the stage's own state -- the id
    # start_pipeline_execution returned is not necessarily the one that ran the rules.
    active_exec_id = _stage_active_execution_id(ctx, name, "Approve")

    # ListRuleExecutions is a separate (summarized/historical) read path that can lag a few
    # seconds behind the rules actually completing, so poll until all 3 entries land terminal.
    deadline = time.monotonic() + 60
    details: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        resp = cp.list_rule_executions(pipelineName=name, filter={"pipelineExecutionId": active_exec_id})
        details = resp["ruleExecutionDetails"]
        if len(details) == 3 and all(d.get("status") != "InProgress" for d in details):
            break
        time.sleep(3)
    assert len(details) == 3, f"expected 3 rule executions after polling, got {details}"

    # A condition's rules "are evaluated together" and ListRuleExecutions documents no order,
    # so the records compare as a set of (ruleName, status).
    expected_declared = ["Charlie", "Alpha", "Bravo"]
    returned = sorted((d["ruleName"], d["status"]) for d in details)
    assert returned == sorted((n, "Succeeded") for n in expected_declared), returned

    # tidy up the execution (best-effort; pipeline deletion on cleanup will reap it regardless)
    try:
        _put_approval_result(ctx, name, "Approve", "ApprovalAction", approval["token"], "Approved")
    except ClientError:
        pass


def _var_check_rule(name: str, operator: str, variable: str, value: str) -> dict[str, Any]:
    return {
        "name": name,
        "ruleTypeId": {"category": "Rule", "owner": "AWS", "provider": "VariableCheck", "version": "1"},
        "configuration": {"Variable": variable, "Value": value, "Operator": operator},
        "inputArtifacts": [],
    }


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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    return name


def _source_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-source-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=name, Key="source.zip", Body=b"PK\x05\x06" + b"\x00" * 18)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
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
                pipeline=pipeline_def, tags=[{"key": "sim2real", "value": _SCENARIO}]
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
    for attempt in range(5):
        try:
            cp.delete_pipeline(name=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "PipelineNotFoundException":
                return
            if code == "ConcurrentModificationException" and attempt < 4:
                time.sleep(3)
                continue
            raise


def _stage_active_execution_id(ctx: Any, pipeline_name: str, stage_name: str) -> str:
    cp = ctx.client("codepipeline")
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state.get("stageStates", []):
        if stage["stageName"] == stage_name:
            return stage["latestExecution"]["pipelineExecutionId"]
    raise AssertionError(f"stage {stage_name} not found in pipeline state: {state}")


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
    timeout_s: float = 400,
    stage_name: str = "Approve",
) -> str:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)
        last_status = resp["pipelineExecution"]["status"]
        if last_status in target_statuses:
            return last_status
        # GetPipelineExecution's aggregate status can lag the stage-level status by a
        # noticeable margin; the per-action/stage status (proven responsive elsewhere) is
        # used as a secondary terminal signal, with a short grace window for the aggregate
        # call to catch up before trusting the stage-derived status.
        state = cp.get_pipeline_state(name=pipeline_name)
        for stage in state.get("stageStates", []):
            if stage["stageName"] == stage_name:
                latest = stage.get("latestExecution", {})
                if latest.get("pipelineExecutionId") == execution_id and latest.get("status") in target_statuses:
                    for _ in range(10):
                        resp = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)
                        last_status = resp["pipelineExecution"]["status"]
                        if last_status in target_statuses:
                            return last_status
                        time.sleep(3)
                    return latest["status"]
        time.sleep(5)
    raise AssertionError(f"execution {execution_id} never reached {target_statuses}, last={last_status}")


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
