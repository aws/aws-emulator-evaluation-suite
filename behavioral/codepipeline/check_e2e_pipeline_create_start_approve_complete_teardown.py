"""e2e-pipeline-create-start-approve-complete-teardown."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pipeline-create-start-approve-complete-teardown"
GROUP = "e2e"
SERVICES = ["codepipeline"]
_SCENARIO = "e2e-pipeline-create-start-approve-complete-teardown"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full lifecycle: create a pipeline, start an execution, resolve its manual
    approval, observe the execution reach Succeeded, then delete the pipeline and
    confirm GetPipeline reports it gone."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _upload_source_zip(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-e2e-")

    pipeline_def = _two_stage_pipeline(name, role_arn, bucket, key)
    _wait_role_usable(
        lambda: cp.create_pipeline(
            pipeline=pipeline_def, tags=[{"key": "sim2real", "value": _SCENARIO}]
        )
    )
    # Safety net: if an assertion fails before the explicit delete_pipeline below
    # runs, this still tears the pipeline down. PipelineNotFoundException means
    # the explicit delete already succeeded, which is fine.
    ctx.on_cleanup(lambda: _safe_delete_pipeline(cp, name))

    # NOTE: CreatePipeline itself auto-starts an initial execution (the
    # "CreatePipeline" trigger type) in addition to the one StartPipelineExecution
    # below explicitly starts. Under the default SUPERSEDED execution mode, either
    # execution could end up being the one that actually reaches/drives the
    # Approve stage. Don't assume it's the exec_id StartPipelineExecution handed
    # back -- read the *actual* driving pipelineExecutionId off the stage state
    # that reached the approval gate.
    cp.start_pipeline_execution(name=name)

    def _probe_state() -> dict:
        return cp.get_pipeline_state(name=name)

    gated = _poll_until(
        _probe_state,
        lambda s: _action_state(s, "Approve", "ApprovalAction").get("latestExecution", {}).get(
            "status"
        )
        == "InProgress",
        timeout_s=120.0,
    )
    exec_id = _stage_state(gated, "Approve")["latestExecution"]["pipelineExecutionId"]
    token = _action_state(gated, "Approve", "ApprovalAction")["latestExecution"]["token"]
    cp.put_approval_result(
        pipelineName=name,
        stageName="Approve",
        actionName="ApprovalAction",
        result={"status": "Approved", "summary": "behavioral-fidelity e2e"},
        token=token,
    )

    def _probe_execution() -> dict:
        return cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=exec_id)[
            "pipelineExecution"
        ]

    # The approval action's own state settles quickly; the aggregate
    # PipelineExecution.status can lag behind it by a bit longer, so confirm the
    # action-level terminal state first (fast, reliable) before waiting on the
    # slower-to-settle execution-level status.
    settled_state = _poll_until(
        _probe_state,
        lambda s: _action_state(s, "Approve", "ApprovalAction")
        .get("latestExecution", {})
        .get("status")
        in ("Succeeded", "Failed"),
        timeout_s=120.0,
    )
    approve_action_status = _action_state(settled_state, "Approve", "ApprovalAction")[
        "latestExecution"
    ]["status"]
    assert approve_action_status == "Succeeded", approve_action_status

    final_exec = _poll_until(
        _probe_execution, lambda e: e["status"] in ("Succeeded", "Failed"), timeout_s=240.0
    )
    assert final_exec["status"] == "Succeeded", final_exec["status"]

    cp.delete_pipeline(name=name)

    refusal = _error_code(lambda: cp.get_pipeline(name=name))
    assert refusal == (
        "PipelineNotFoundException",
        f"Account '{ctx.account}' does not have a pipeline with name '{name}'",
    ), refusal

    # The pipeline is not just absent from GetPipeline -- it is unusable. A mutation
    # against the now-deleted name must fail the same way, not silently create a new
    # execution against nothing.
    start_refusal = _error_code(lambda: cp.start_pipeline_execution(name=name))
    assert start_refusal == (
        "PipelineNotFoundException",
        f"Pipeline with name {name} does not exist in account {ctx.account}.",
    ), start_refusal


def _error_code(fn) -> tuple[str, str]:
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _safe_delete_pipeline(cp, name: str) -> None:
    try:
        cp.delete_pipeline(name=name)
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "PipelineNotFoundException":
            raise


def _stage_state(state_resp: dict, stage_name: str) -> dict:
    for stage in state_resp["stageStates"]:
        if stage["stageName"] == stage_name:
            return stage
    raise AssertionError(f"stage {stage_name} not found")


def _action_state(state_resp: dict, stage_name: str, action_name: str) -> dict:
    for stage in state_resp["stageStates"]:
        if stage["stageName"] == stage_name:
            for action in stage["actionStates"]:
                if action["actionName"] == action_name:
                    return action
    raise AssertionError(f"action {action_name} not found in stage {stage_name}")


def _poll_until(probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]}
    )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup() -> None:
        resp = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_source_zip(ctx, bucket: str, key: str = "source.zip") -> str:
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real-behavioral-source")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return key


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codepipeline.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cp-policy-")
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:PutObject",
                        "s3:GetBucketVersioning",
                        "s3:ListBucket",
                    ],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _wait_role_usable(fn, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> Any:
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


def _two_stage_pipeline(name: str, role_arn: str, bucket: str, source_key: str) -> dict:
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
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
                        "outputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": {
                            "S3Bucket": bucket,
                            "S3ObjectKey": source_key,
                            "PollForSourceChanges": "false",
                        },
                        "runOrder": 1,
                    }
                ],
            },
            {
                "name": "Approve",
                "actions": [
                    {
                        "name": "ApprovalAction",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                        "runOrder": 1,
                    }
                ],
            },
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
