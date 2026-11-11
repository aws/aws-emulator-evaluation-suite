"""e2e-pipeline-create-run-approve-teardown."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pipeline-create-run-approve-teardown"
GROUP = "state-machine"
SERVICES = ["codepipeline"]

_TERMINAL = {"Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full flow: create a pipeline with a manual-approval stage, start an execution,
    approve it via PutApprovalResult, observe the stage (and the overall execution)
    reach Succeeded, then delete the pipeline and confirm it is gone."""
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")

    source_bucket = _create_bucket(ctx, "e2e-src")
    artifact_bucket = _create_bucket(ctx, "e2e-art")
    s3.put_object(Bucket=source_bucket, Key="app.zip", Body=_make_zip_bytes())
    role_arn = _create_pipeline_role(ctx, [source_bucket, artifact_bucket])

    name = ctx.unique_name("sim2real-cp-e2e-")
    pipeline_def = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [_source_stage(source_bucket, "app.zip"), _approval_stage()],
    }
    _wait_role_usable(
        lambda: cp.create_pipeline(
            pipeline=pipeline_def, tags=[{"key": "sim2real", "value": CHECK}]
        )
    )
    _register_pipeline_cleanup(ctx, cp, name)

    def _approval_action_state():
        state = cp.get_pipeline_state(name=name)
        approval_stage = next(s for s in state["stageStates"] if s["stageName"] == "Approval")
        return next(
            a for a in approval_stage["actionStates"] if a["actionName"] == "ApprovalAction"
        )

    # CreatePipeline auto-triggers an initial execution of its own. In SUPERSEDED
    # execution mode that execution would otherwise occupy the Approval action ahead
    # of the execution we explicitly start below, causing our token/exec-id tracking
    # to target the wrong execution. Drain it first so the pipeline is idle.
    initial_awaiting = _poll_until(
        _approval_action_state,
        lambda a: a.get("latestExecution", {}).get("status") == "InProgress"
        and "token" in a.get("latestExecution", {}),
        timeout_s=180.0,
        interval_s=5.0,
    )
    cp.put_approval_result(
        pipelineName=name,
        stageName="Approval",
        actionName="ApprovalAction",
        result={"summary": "drain initial auto-triggered execution", "status": "Approved"},
        token=initial_awaiting["latestExecution"]["token"],
    )
    _poll_until(
        _approval_action_state,
        lambda a: a.get("latestExecution", {}).get("status") == "Succeeded",
        timeout_s=90.0,
        interval_s=3.0,
    )

    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]

    awaiting = _poll_until(
        _approval_action_state,
        lambda a: a.get("latestExecution", {}).get("status") == "InProgress"
        and "token" in a.get("latestExecution", {})
        and a["latestExecution"]["token"] != initial_awaiting["latestExecution"]["token"],
        timeout_s=180.0,
        interval_s=5.0,
    )
    token = awaiting["latestExecution"]["token"]

    cp.put_approval_result(
        pipelineName=name,
        stageName="Approval",
        actionName="ApprovalAction",
        result={"summary": "sim2real e2e approval", "status": "Approved"},
        token=token,
    )

    _poll_until(
        _approval_action_state,
        lambda a: a.get("latestExecution", {}).get("status") == "Succeeded",
        timeout_s=90.0,
        interval_s=3.0,
    )

    execution = _poll_execution(
        cp, name, exec_id, lambda e: e["status"] in _TERMINAL, timeout_s=180.0, interval_s=5.0
    )
    assert execution["status"] == "Succeeded", (
        f"expected the approved execution to reach Succeeded, got {execution['status']!r}"
    )

    cp.delete_pipeline(name=name)
    read_refusal = _error_code(lambda: cp.get_pipeline(name=name))
    assert read_refusal == (
        "PipelineNotFoundException",
        f"Account '{ctx.account}' does not have a pipeline with name '{name}'",
    ), f"expected GetPipeline on the deleted pipeline to report PipelineNotFoundException, got {read_refusal!r}"
    mutate_refusal = _error_code(lambda: cp.start_pipeline_execution(name=name))
    assert mutate_refusal == (
        "PipelineNotFoundException",
        f"Pipeline with name {name} does not exist in account {ctx.account}.",
    ), (
        f"expected StartPipelineExecution against the deleted pipeline to also report "
        f"PipelineNotFoundException, got {mutate_refusal!r}"
    )


# ===== helpers =====

def _make_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.txt", "hello-codepipeline")
    return buf.getvalue()


def _create_bucket(ctx, suffix: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-cp-{suffix}-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup():
        try:
            versions = s3.list_object_versions(Bucket=name)
            to_delete = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
            ]
            if to_delete:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": to_delete}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _create_pipeline_role(ctx, bucket_names: list) -> str:
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    resources = []
    for b in bucket_names:
        resources.append(f"arn:aws:s3:::{b}")
        resources.append(f"arn:aws:s3:::{b}/*")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": resources}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _source_stage(bucket: str, key: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "SourceAction",
                "actionTypeId": {
                    "category": "Source",
                    "owner": "AWS",
                    "provider": "S3",
                    "version": "1",
                },
                "outputArtifacts": [{"name": "SourceArtifact"}],
                "configuration": {
                    "S3Bucket": bucket,
                    "S3ObjectKey": key,
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
                "name": "ApprovalAction",
                "actionTypeId": {
                    "category": "Approval",
                    "owner": "AWS",
                    "provider": "Manual",
                    "version": "1",
                },
            }
        ],
    }


def _wait_role_usable(fn, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> Any:
    """Bounded retry for the window between IAM role/policy creation and the role
    becoming assumable by CodePipeline, in place of a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in (
                "InvalidStructureException",
                "InvalidParameterValueException",
                "InvalidRoleException",
            ) or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _register_pipeline_cleanup(ctx, cp, name: str) -> None:
    def _cleanup():
        try:
            cp.delete_pipeline(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PipelineNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _poll_execution(cp, name, exec_id, predicate, timeout_s=180.0, interval_s=5.0):
    """Poll GetPipelineExecution, tolerating the brief propagation window right
    after StartPipelineExecution where the new execution id is not yet visible."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cp.get_pipeline_execution(
                pipelineName=name, pipelineExecutionId=exec_id
            )["pipelineExecution"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                time.sleep(interval_s)
                continue
            raise
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
