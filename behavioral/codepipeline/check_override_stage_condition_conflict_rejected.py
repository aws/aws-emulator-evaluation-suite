"""override-stage-condition-conflict-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "override-stage-condition-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["codepipeline"]
_SCENARIO = "codepipeline-override-stage-condition-conflict-rejected"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Overriding a failed BEFORE_ENTRY condition marks it Overridden and lets the stage run;
    a second override of the resolved condition is ConditionNotOverridableException."""
    cp = ctx.client("codepipeline")
    # A ConflictException race on an open condition is timing-dependent, so only the
    # deterministic already-resolved rejection is asserted.
    setup = _create_gated_pipeline(ctx)
    name = setup["name"]
    exec_id = setup["exec_id"]

    condition_status = _wait_for_condition_status(ctx, name, {"Failed"})
    assert condition_status == "Failed"

    cp.override_stage_condition(
        pipelineName=name,
        stageName=_APPROVAL_STAGE,
        pipelineExecutionId=exec_id,
        conditionType="BEFORE_ENTRY",
    )
    overridden_status = _wait_for_condition_status(ctx, name, {"Overridden"})
    assert overridden_status == "Overridden"

    token = _wait_for_approval_token(ctx, name)
    cp.put_approval_result(
        pipelineName=name,
        stageName=_APPROVAL_STAGE,
        actionName=_APPROVAL_ACTION,
        result={"summary": "approve-after-override", "status": "Approved"},
        token=token,
    )
    final_status = _poll_execution_status(ctx, name, exec_id, {"Succeeded", "Failed"})
    assert final_status == "Succeeded"

    refusal = _error_code(
        lambda: cp.override_stage_condition(
            pipelineName=name,
            stageName=_APPROVAL_STAGE,
            pipelineExecutionId=exec_id,
            conditionType="BEFORE_ENTRY",
        )
    )
    # AWS names the pipeline, not the execution id, in the "execution '...'" slot.
    assert refusal == (
        "ConditionNotOverridableException",
        f"The condition type BEFORE_ENTRY in stage {_APPROVAL_STAGE} cannot be overridden now. Either it contains no "
        f"failed or in-progress rule, the execution '{name}' is already superseded, or the "
        f"pipeline definition has changed since the rules(s) failed.",
    ), refusal

    state = cp.get_pipeline_state(name=name)
    approval_stage = next(s for s in state["stageStates"] if s["stageName"] == _APPROVAL_STAGE)
    assert _condition_status(approval_stage) == "Overridden"


_SOURCE_STAGE = "Source"
_SOURCE_ACTION = "SourceAction"
_APPROVAL_STAGE = "Approval"
_APPROVAL_ACTION = "ApprovalAction"
_GATE_VARIABLE = "gateStatus"


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _create_source_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-src-")
    # us-east-1 is S3's own API special case: CreateBucket rejects an explicit
    # LocationConstraint for it, so this branch pins that literal, not the check's region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})

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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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


def _gated_pipeline_declaration(name: str, role_arn: str, bucket: str, key: str) -> dict[str, Any]:
    return {
        "name": name,
        "roleArn": role_arn,
        "pipelineType": "V2",
        "artifactStore": {"type": "S3", "location": bucket},
        "variables": [
            {"name": _GATE_VARIABLE, "defaultValue": "block"},
        ],
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
                # "block" never equals "go", so the rule fails every execution with an
                # overridable FAIL (a Skip result is documented as never overridable).
                "beforeEntry": {
                    "conditions": [
                        {
                            "result": "FAIL",
                            "rules": [
                                {
                                    "name": "GateCheck",
                                    "ruleTypeId": {
                                        "category": "Rule",
                                        "owner": "AWS",
                                        "provider": "VariableCheck",
                                        "version": "1",
                                    },
                                    "configuration": {
                                        "Variable": f"#{{variables.{_GATE_VARIABLE}}}",
                                        "Value": "go",
                                        "Operator": "EQ",
                                    },
                                    "inputArtifacts": [],
                                }
                            ],
                        }
                    ]
                },
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


def _create_pipeline_with_role_propagation(cp, declaration, *, tags, timeout_s: float) -> None:
    """Retry CreatePipeline while it answers InvalidStructureException for a still-propagating role.

    IAM exposes no condition to poll for propagation, so the bounded retry is the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cp.create_pipeline(pipeline=declaration, tags=tags)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (
                err.get("Code") == "InvalidStructureException"
                and "AssumeRole" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_gated_pipeline(ctx) -> dict[str, str]:
    bucket = _create_source_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pipe-")
    decl = _gated_pipeline_declaration(name, role_arn, bucket, "source.zip")
    _create_pipeline_with_role_propagation(
        cp, decl, tags=[{"key": "sim2real", "value": _SCENARIO}], timeout_s=60.0
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    exec_id = _wait_for_first_execution(ctx, name)
    return {"name": name, "exec_id": exec_id}


def _wait_for_first_execution(ctx, pipeline_name: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    """CreatePipeline auto-triggers an execution, but it can take a moment before
    ListPipelineExecutions reports it."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"]
        if execs:
            return execs[0]["pipelineExecutionId"]
        time.sleep(interval_s)
    raise AssertionError(f"no pipeline execution appeared for {pipeline_name} within {timeout_s}s")


def _get_action_state(ctx, pipeline_name: str, stage_name: str, action_name: str) -> dict[str, Any] | None:
    cp = ctx.client("codepipeline")
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state.get("stageStates", []):
        if stage["stageName"] == stage_name:
            for action in stage.get("actionStates", []):
                if action["actionName"] == action_name:
                    return action
    return None


def _condition_status(approval_stage: dict[str, Any]) -> str:
    """The stage's single BEFORE_ENTRY condition status, nested under
    beforeEntryConditionState.conditionStates[0].latestExecution.status."""
    condition_states = approval_stage.get("beforeEntryConditionState", {}).get("conditionStates", [])
    if not condition_states:
        return ""
    return condition_states[0].get("latestExecution", {}).get("status", "")


def _wait_for_condition_status(
    ctx, pipeline_name: str, target_statuses: set[str], timeout_s: float = 240.0, interval_s: float = 3.0
) -> str:
    """Poll the Approval stage's BEFORE_ENTRY condition status, retrying a Source stage that
    failed on a still-propagating IAM role a bounded number of times."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    source_retries = 0
    max_source_retries = 4
    last = ""
    while time.monotonic() < deadline:
        state = cp.get_pipeline_state(name=pipeline_name)
        approval_stage = next(
            (s for s in state.get("stageStates", []) if s["stageName"] == _APPROVAL_STAGE), None
        )
        if approval_stage:
            last = _condition_status(approval_stage)
            if last in target_statuses:
                return last
        source_action = _get_action_state(ctx, pipeline_name, _SOURCE_STAGE, _SOURCE_ACTION)
        if source_action and source_retries < max_source_retries:
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
                    source_retries += 1

                except ClientError:
                    pass
        time.sleep(interval_s)
    raise AssertionError(
        f"before-entry condition for {pipeline_name} never reached {target_statuses}, last saw {last!r}, "
        f"source action status {source_action.get('latestExecution', {}).get('status') if source_action else None!r}"
    )


def _wait_for_approval_token(ctx, pipeline_name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        action = _get_action_state(ctx, pipeline_name, _APPROVAL_STAGE, _APPROVAL_ACTION)
        if action:
            token = action.get("latestExecution", {}).get("token")
            if token:
                return token
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
