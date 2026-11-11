"""rollback-stage-restores-previous-execution."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rollback-stage-restores-previous-execution"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RollbackStage creates a new ROLLBACK-type pipeline execution that targets a
    prior successful execution of the stage, and that lineage (rollbackMetadata /
    executionType) is durably visible via GetPipelineExecution."""
    cp = ctx.client("codepipeline")
    setup = _setup_ready_pipeline(ctx)
    name = setup["name"]
    target_execution_id = setup["first_execution_id"]  # the auto-drained, successful execution

    exec2_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    token2 = _wait_for_approval_token(ctx, name)
    cp.put_approval_result(
        pipelineName=name, stageName=_APPROVAL_STAGE, actionName=_APPROVAL_ACTION,
        result={"summary": "approve-2nd", "status": "Approved"}, token=token2,
    )
    _poll_execution_status(ctx, name, exec2_id, {"Succeeded"})

    rollback_resp = cp.rollback_stage(
        pipelineName=name, stageName=_APPROVAL_STAGE, targetPipelineExecutionId=target_execution_id
    )
    rollback_exec_id = rollback_resp["pipelineExecutionId"]
    assert rollback_exec_id not in (target_execution_id, exec2_id), (
        f"RollbackStage returned an execution id ({rollback_exec_id!r}) that reuses one already "
        f"in play (target {target_execution_id!r}, exec2 {exec2_id!r}); it must mint a new one"
    )

    rollback_execution = _get_execution_with_retry(ctx, name, rollback_exec_id)
    assert rollback_execution["executionType"] == "ROLLBACK", (
        f"execution {rollback_exec_id!r} started via RollbackStage reports executionType "
        f"{rollback_execution.get('executionType')!r}, expected 'ROLLBACK'"
    )
    assert rollback_execution["rollbackMetadata"]["rollbackTargetPipelineExecutionId"] == target_execution_id, (
        f"rollbackMetadata does not name the targeted execution: "
        f"{rollback_execution['rollbackMetadata']!r}, expected target {target_execution_id!r}"
    )

    # let the rolled-back execution run to completion to confirm it is a real,
    # functioning pipeline execution and not just a metadata stub
    rollback_token = _wait_for_approval_token(ctx, name)
    cp.put_approval_result(
        pipelineName=name, stageName=_APPROVAL_STAGE, actionName=_APPROVAL_ACTION,
        result={"summary": "approve-rollback", "status": "Approved"}, token=rollback_token,
    )
    final_status = _poll_execution_status(ctx, name, rollback_exec_id, {"Succeeded", "Failed"})
    assert final_status == "Succeeded", (
        f"the rollback execution {rollback_exec_id!r} did not run to completion after approval: "
        f"reported {final_status!r}, expected 'Succeeded'"
    )

    # the original target execution is untouched by the rollback
    target_status = cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=target_execution_id)[
        "pipelineExecution"
    ]["status"]
    assert target_status == "Succeeded", (
        f"the execution the rollback targeted, {target_execution_id!r}, no longer reports "
        f"'Succeeded' after being rolled back to: reports {target_status!r}"
    )


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
    # CreatePipeline validates that it can assume roleArn, so it answers
    # InvalidStructureException while the freshly created role is still propagating through IAM.
    # IAM exposes no condition to poll for that, so this bounded retry on the SPECIFIC transient
    # error IS the wait; any other failure raises immediately instead of being masked by retries.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=decl, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as e:
            err = e.response.get("Error", {})
            transient = (
                err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get("Message", "")
            )
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
        try:
            resp = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                time.sleep(interval_s)
                continue
            raise
        last = resp["pipelineExecution"]["status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {execution_id} did not reach {terminal_statuses}, last saw {last}")


def _get_execution_with_retry(
    ctx, pipeline_name: str, execution_id: str, timeout_s: float = 30.0, interval_s: float = 2.0
) -> dict[str, Any]:
    """GetPipelineExecution called immediately after RollbackStage/StartPipelineExecution
    can transiently 404 while the execution record propagates; retry briefly."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)[
                "pipelineExecution"
            ]
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
        pipelineName=pipeline_name, stageName=_APPROVAL_STAGE, actionName=_APPROVAL_ACTION,
        result={"summary": "auto-drain initial execution", "status": "Approved"}, token=token,
    )
    _poll_execution_status(ctx, pipeline_name, first_exec_id, {"Succeeded"})
    return {"name": pipeline_name, "bucket": bucket, "role_arn": role_arn, "first_execution_id": first_exec_id}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
