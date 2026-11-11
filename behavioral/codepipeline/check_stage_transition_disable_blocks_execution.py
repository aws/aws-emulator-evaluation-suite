"""stage-transition-disable-blocks-execution."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stage-transition-disable-blocks-execution"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DisableStageTransition (Inbound) keeps a started execution queued at the
    transition into that stage instead of advancing it; EnableStageTransition
    lets the same execution resume and reach the deployed target."""
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")

    role_arn = _create_service_role(ctx)
    artifact_bucket = _create_bucket(ctx, versioned=False)
    source_bucket = _create_bucket(ctx, versioned=True)
    target_bucket = _create_bucket(ctx, versioned=False)
    source_key = "src/app.zip"
    payload = b"disable-transition-payload"
    _put_zip_object(ctx, source_bucket, source_key, "app.txt", payload)

    name = ctx.unique_name("sim2real-cp-disable-")
    pipeline_decl = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [
            _source_stage(source_bucket, source_key),
            _deploy_stage(target_bucket),
        ],
    }
    _create_pipeline_with_backoff(cp, pipeline_decl)
    ctx.on_cleanup(lambda: _delete_pipeline(cp, name))

    reason = "sim2real-behavioral-block"
    cp.disable_stage_transition(
        pipelineName=name, stageName="Deploy", transitionType="Inbound", reason=reason
    )

    disabled_state = _stage_state(cp.get_pipeline_state(name=name), "Deploy")
    assert disabled_state["inboundTransitionState"]["enabled"] is False
    assert disabled_state["inboundTransitionState"]["disabledReason"] == reason

    start_resp = _start_execution_with_backoff(cp, name)
    execution_id = start_resp["pipelineExecutionId"]

    # Wait for Source to actually finish for this execution -- proof the
    # pipeline is making progress at all.
    _poll_until(
        lambda: _action_status(cp, name, "Source", "Source", execution_id),
        lambda s: s == "Succeeded",
        timeout_s=60.0,
        interval_s=2.0,
    )

    # Give the (now-finished) execution a generous grace window during which
    # it would, if the inbound transition were not disabled, have entered and
    # completed the trivial S3 Deploy action. It must NOT advance while the
    # transition stays disabled.
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        deploy_state = _stage_state(cp.get_pipeline_state(name=name), "Deploy")
        assert deploy_state["inboundTransitionState"]["enabled"] is False
        assert (
            deploy_state.get("latestExecution", {}).get("pipelineExecutionId") != execution_id
        ), "Deploy stage must not have started processing the blocked execution"
        time.sleep(2.0)

    cp.enable_stage_transition(pipelineName=name, stageName="Deploy", transitionType="Inbound")

    final_status = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ]["status"],
        lambda s: s in ("Succeeded", "Failed", "Stopped", "Superseded"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final_status == "Succeeded"

    resumed_state = _stage_state(cp.get_pipeline_state(name=name), "Deploy")
    assert resumed_state["latestExecution"]["pipelineExecutionId"] == execution_id
    assert resumed_state["latestExecution"]["status"] == "Succeeded"
    assert resumed_state["inboundTransitionState"]["enabled"] is True

    deployed = s3.get_object(Bucket=target_bucket, Key="app.txt")["Body"].read()
    assert deployed == payload


# ===== helpers =====


def _action_status(cp, pipeline_name: str, stage_name: str, action_name: str, execution_id: str):
    state = cp.get_pipeline_state(name=pipeline_name)
    stage = _stage_state(state, stage_name)
    for action in stage.get("actionStates", []):
        if action["actionName"] == action_name:
            latest = action.get("latestExecution", {})
            if latest.get("actionExecutionId") is None and latest.get("status") is None:
                return None
            return latest.get("status")
    return None



def _delete_pipeline(cp, name):
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _create_pipeline_with_backoff(cp, pipeline_decl: dict, deadline_s: float = 60.0):
    """CreatePipeline validates the service role is assumable before anything else, and a
    freshly-created role has not always propagated yet; retry only that specific transient
    (InvalidStructureException naming AssumeRole), never a genuine structural rejection."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return cp.create_pipeline(
                pipeline=pipeline_decl, tags=[{"key": "sim2real", "value": CHECK}]
            )
        except ClientError as e:
            err = e.response.get("Error", {})
            transient = err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get(
                "Message", ""
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _start_execution_with_backoff(cp, name: str, attempts: int = 5):
    """StartPipelineExecution can be throttled right after a pipeline is
    created/updated in a busy account; retry with explicit backoff beyond
    botocore's default retry budget instead of letting ThrottlingException
    propagate."""
    last_err = None
    for i in range(attempts):
        try:
            return cp.start_pipeline_execution(name=name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException"):
                last_err = e
                time.sleep(1.5 * (i + 1))
                continue
            raise
    raise AssertionError(f"start_pipeline_execution kept throttling: {last_err}")


def _source_stage(source_bucket: str, source_key: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {
                    "category": "Source",
                    "owner": "AWS",
                    "provider": "S3",
                    "version": "1",
                },
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {
                    "S3Bucket": source_bucket,
                    "S3ObjectKey": source_key,
                    "PollForSourceChanges": "false",
                },
            }
        ],
    }


def _deploy_stage(target_bucket: str) -> dict:
    return {
        "name": "Deploy",
        "actions": [
            {
                "name": "Deploy",
                "actionTypeId": {
                    "category": "Deploy",
                    "owner": "AWS",
                    "provider": "S3",
                    "version": "1",
                },
                "inputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {"BucketName": target_bucket, "Extract": "true"},
            }
        ],
    }


def _stage_state(state: dict, stage_name: str) -> dict:
    for s in state["stageStates"]:
        if s["stageName"] == stage_name:
            return s
    raise AssertionError(f"stage {stage_name} not found in pipeline state")


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _zip_bytes(filename: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def _put_zip_object(ctx, bucket: str, key: str, filename: str, content: bytes) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=_zip_bytes(filename, content))


def _create_bucket(ctx, versioned: bool) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    if versioned:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            _empty_bucket(ctx, bucket)
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _create_service_role(ctx, extra_statements=None) -> str:
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    statements = [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]
    if extra_statements:
        statements.extend(extra_statements)
    policy = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    # IAM role/policy propagation is eventually consistent (no fixed documented window)
    # and not independently observable here; _create_pipeline_with_backoff's bounded
    # retry on InvalidStructureException is what actually absorbs the remaining lag.
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
