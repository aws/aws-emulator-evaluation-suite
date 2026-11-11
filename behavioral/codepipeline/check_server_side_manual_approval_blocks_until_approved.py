"""server-side-manual-approval-blocks-until-approved."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-manual-approval-blocks-until-approved"
GROUP = "server-side"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A manual approval action genuinely halts server-side pipeline progression: the execution
    stays InProgress across a bounded observation window with no client polling/enforcement,
    and only calling PutApprovalResult lets the execution reach its terminal Succeeded state."""
    cp = ctx.client("codepipeline")
    bucket, key = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = _create_pipeline(
        ctx, [_source_stage(bucket, key), _approval_stage("Approval", "Approve")], role_arn, bucket
    )

    # CodePipeline auto-starts an execution the moment the pipeline is created; it will also
    # reach and block on the Approval action. Drain it (reject it) first so its token/gate
    # doesn't get confused with the execution we explicitly start and track below.
    _drain_initial_approval(ctx, name, "Approval", "Approve")

    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    token = _wait_for_approval_token(ctx, name, "Approval", "Approve", timeout_s=90)

    # Bounded observation window: with nobody responding, the execution must stay InProgress --
    # the service itself is the one holding the gate, not something the client must enforce.
    for _ in range(3):
        time.sleep(5)
        exec_status = cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=exec_id)[
            "pipelineExecution"
        ]["status"]
        assert exec_status == "InProgress", exec_status

    cp.put_approval_result(
        pipelineName=name,
        stageName="Approval",
        actionName="Approve",
        result={"summary": "approved by check", "status": "Approved"},
        token=token,
    )

    final_status = _wait_for_execution_status(ctx, name, exec_id, "Succeeded", timeout_s=60)
    assert final_status == "Succeeded", final_status


_PREFIX = "sim2real-cpbeh-"


def _safe_bucket_name(ctx, base: str) -> str:
    raw = ctx.unique_name(base).lower()
    raw = re.sub(r"[^a-z0-9.-]", "-", raw)
    return raw[:63]


def _make_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("buildspec.yml", "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n")
    return buf.getvalue()


def _create_artifact_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = _safe_bucket_name(ctx, _PREFIX + "art-")
    # us-east-1 is S3's global default endpoint: CreateBucketConfiguration.LocationConstraint
    # must be omitted there or the call is rejected. Every other region requires it.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _PREFIX.rstrip("-")}]})
    key = "source.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_make_zip_bytes())
    return bucket, key


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(_PREFIX + "role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _PREFIX.rstrip("-")}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetBucketVersioning", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="cp-inline", PolicyDocument=json.dumps(policy_doc))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="cp-inline")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _source_stage(bucket: str, key: str) -> dict[str, Any]:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
                "runOrder": 1,
            }
        ],
    }


def _approval_stage(stage_name: str, action_name: str) -> dict[str, Any]:
    return {
        "name": stage_name,
        "actions": [
            {
                "name": action_name,
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                "configuration": {},
                "runOrder": 1,
            }
        ],
    }


def _create_pipeline(ctx, stages: list[dict[str, Any]], role_arn: str, bucket: str, timeout_s: float = 90.0) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name(_PREFIX + "pipe-")
    pipeline_dict = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = cp.create_pipeline(
                pipeline=pipeline_dict,
                tags=[{"key": "sim2real", "value": _PREFIX.rstrip("-")}],
            )
            ctx.on_cleanup(lambda n=name: cp.delete_pipeline(name=n))
            return resp["pipeline"]["name"]
        except ClientError as e:
            last_exc = e
            time.sleep(3)
    raise AssertionError(f"create_pipeline never succeeded: {last_exc}")


def _get_action_state(ctx, pipeline_name: str, stage_name: str, action_name: str) -> dict[str, Any] | None:
    cp = ctx.client("codepipeline")
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state["stageStates"]:
        if stage["stageName"] != stage_name:
            continue
        for action in stage.get("actionStates", []):
            if action["actionName"] == action_name:
                return action
    return None


def _wait_for_approval_token(ctx, pipeline_name: str, stage_name: str, action_name: str, timeout_s: float = 90.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        action = _get_action_state(ctx, pipeline_name, stage_name, action_name)
        if action:
            latest = action.get("latestExecution", {})
            if latest.get("status") == "InProgress" and latest.get("token"):
                return latest["token"]
        time.sleep(3)
    raise AssertionError("approval action never reached InProgress with a token")


def _drain_initial_approval(ctx, pipeline_name: str, stage_name: str, action_name: str, timeout_s: float = 180.0) -> None:
    """Reject the auto-triggered execution's approval (if it reaches one) and wait until no execution is InProgress."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    rejected = False
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs and all(e["status"] != "InProgress" for e in execs):
            return
        if execs and not rejected:
            latest = (_get_action_state(ctx, pipeline_name, stage_name, action_name) or {}).get("latestExecution", {})
            if latest.get("status") == "InProgress" and latest.get("token"):
                cp.put_approval_result(
                    pipelineName=pipeline_name,
                    stageName=stage_name,
                    actionName=action_name,
                    result={"summary": "draining initial auto-triggered execution", "status": "Rejected"},
                    token=latest["token"],
                )
                rejected = True
        time.sleep(3)
    raise AssertionError("initial auto-triggered pipeline execution never drained")


def _wait_for_execution_status(ctx, pipeline_name: str, execution_id: str, expected: str, timeout_s: float = 60.0) -> str:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        last = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ]["status"]
        if last == expected:
            return last
        time.sleep(3)
    raise AssertionError(f"execution never reached {expected!r}, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
