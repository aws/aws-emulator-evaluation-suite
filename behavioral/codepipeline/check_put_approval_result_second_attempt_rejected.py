"""put-approval-result-second-attempt-rejected."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-approval-result-second-attempt-rejected"
GROUP = "concurrency"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two racing PutApprovalResult calls on one token, exactly one wins and the execution follows its
    verdict, the other and a later call fail with ApprovalAlreadyCompletedException and its exact message, and
    a fresh approval still succeeds.
    """
    cp = ctx.client("codepipeline")
    setup = _setup_ready_pipeline(ctx)
    name = setup["name"]
    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    token = _wait_for_approval_token(ctx, name)

    def _race(summary: str, status: str):
        # Either outcome is legitimate for a racer: None when it wins, the Error dict when it loses.
        try:
            cp.put_approval_result(
                pipelineName=name, stageName=_APPROVAL_STAGE, actionName=_APPROVAL_ACTION,
                result={"summary": summary, "status": status}, token=token,
            )
        except ClientError as e:
            return e.response.get("Error", {})
        return None

    def _approve():
        return _race("racer-approve", "Approved")

    def _reject():
        return _race("racer-reject", "Rejected")

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_approve = pool.submit(_approve)
        f_reject = pool.submit(_reject)
        approve_code = f_approve.result()
        reject_code = f_reject.result()

    codes = [approve_code, reject_code]
    winners = [c for c in codes if c is None]
    losers = [c for c in codes if c is not None]
    assert len(winners) == 1, f"exactly one racer should win the approval, got {codes}"
    assert len(losers) == 1, f"exactly one racer should lose the approval, got {codes}"
    assert losers[0].get("Code") == "ApprovalAlreadyCompletedException", (
        f"the losing racer must be rejected with ApprovalAlreadyCompletedException, got {losers[0]}"
    )
    expected_message = (
        "The approval request that you responded to is already complete or has expired. "
        "Review the latest revisions in the pipeline, and then try again."
    )
    assert losers[0].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {losers[0].get('Message')!r}"
    )

    final_status = _poll_execution_status(ctx, name, exec_id, {"Succeeded", "Failed"})
    if approve_code is None:
        assert final_status == "Succeeded", (
            f"the approve racer won, so the execution must reach Succeeded, got {final_status}"
        )
    else:
        assert final_status == "Failed", (
            f"the reject racer won, so the execution must reach Failed, got {final_status}"
        )

    # a later attempt against the completed approval is rejected too, proving
    # the outcome is durable, not a transient race artifact
    late = _error(
        lambda: cp.put_approval_result(
            pipelineName=name, stageName=_APPROVAL_STAGE, actionName=_APPROVAL_ACTION,
            result={"summary": "late-attempt", "status": "Approved"}, token=token,
        )
    )
    assert late.get("Code") == "ApprovalAlreadyCompletedException", (
        f"a later call against the same resolved token must still be rejected, got {late!r}"
    )
    assert late.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {late.get('Message')!r}"
    )

    # positive control: a fresh approval on a brand-new execution still completes
    exec2_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    token2 = _wait_for_approval_token(ctx, name)
    cp.put_approval_result(
        pipelineName=name, stageName=_APPROVAL_STAGE, actionName=_APPROVAL_ACTION,
        result={"summary": "control-approve", "status": "Approved"}, token=token2,
    )
    control_status = _poll_execution_status(ctx, name, exec2_id, {"Succeeded", "Failed"})
    assert control_status == "Succeeded", (
        f"a fresh, uncontested approval must still complete the pipeline, got {control_status}"
    )


_SOURCE_STAGE = "Source"
_SOURCE_ACTION = "SourceAction"
_APPROVAL_STAGE = "Approval"
_APPROVAL_ACTION = "ApprovalAction"


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_source_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-src-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this is S3's API quirk, not an assumption about which region the check runs in.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "put-approval-result-second-attempt-rejected"}]})

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
        Tags=[{"Key": "sim2real", "Value": "put-approval-result-second-attempt-rejected"}],
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
    _create_with_role_propagation(cp, decl, timeout_s=60.0)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _create_with_role_propagation(cp, declaration, *, timeout_s: float) -> None:
    """IAM role propagation is real: CreatePipeline can transiently report the just-created
    role as unassumable. Retry only that specific transient, never a structural rejection."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cp.create_pipeline(pipeline=declaration)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = err.get("Code") in ("InvalidStructureException", "ValidationException") and (
                "AssumeRole" in err.get("Message", "") or "assume" in err.get("Message", "").lower()
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


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
