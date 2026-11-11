"""retry-stage-not-latest-execution-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-stage-not-latest-execution-rejected"
GROUP = "concurrency"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RetryStageExecution on an execution that is no longer the stage's latest is rejected with
    StageNotRetryableException and leaves the stage's latest execution unchanged, while retrying
    the latest execution succeeds."""
    cp = ctx.client("codepipeline")

    role_arn = _create_service_role(ctx)
    artifact_bucket = _create_bucket(ctx)
    source_bucket = _create_bucket(ctx, versioned=True)
    source_key = "src/app.zip"
    _put_zip_object(ctx, source_bucket, source_key, "app.txt", b"retry-test-payload")

    # Deploy target bucket is intentionally never created, so the Deploy
    # action fails deterministically (NoSuchBucket) on every execution.
    missing_bucket = ctx.unique_name("sim2real-cp-missing-")

    name = ctx.unique_name("sim2real-cp-retry-")
    pipeline_decl = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [
            _source_stage(source_bucket, source_key),
            _deploy_stage(missing_bucket),
        ],
    }
    timeout_s = 180
    _create_with_role_propagation(cp, pipeline_decl, timeout_s=timeout_s)
    ctx.on_cleanup(lambda: _delete_pipeline(cp, name))

    execution_id_1 = _run_to_terminal(cp, name, "Failed")
    execution_id_2 = _run_to_terminal(cp, name, "Failed")
    assert execution_id_1 != execution_id_2, (
        f"two runs of the same pipeline must get distinct execution ids, got {execution_id_1!r} twice"
    )

    deploy_state = _stage_state(cp.get_pipeline_state(name=name), "Deploy")
    assert deploy_state["latestExecution"]["pipelineExecutionId"] == execution_id_2, (
        f"expected latestExecution={execution_id_2!r}, "
        f"got {deploy_state['latestExecution']['pipelineExecutionId']!r}"
    )

    code, message = _error(
        lambda: cp.retry_stage_execution(
            pipelineName=name,
            stageName="Deploy",
            pipelineExecutionId=execution_id_1,
            retryMode="ALL_ACTIONS",
        )
    )
    # Once a newer execution has run
    # the same stage, CodePipeline no longer has a retryable record tied to
    # the older execution id and reports StageNotRetryableException, not
    # NotLatestPipelineExecutionException (which the docs describe for the
    # narrower race where a newer FAILED run supersedes an in-flight retry of
    # what was, at request time, still the latest execution).
    assert code == "StageNotRetryableException", f"got code={code!r}"
    assert message == (
        f"The stage named Deploy in the {name} pipeline can't be retried now. Either it contains "
        f"no failed actions, the execution '{execution_id_1}' is already superseded, or the "
        "pipeline definition has changed since the action(s) failed."
    ), message

    unaffected_state = _stage_state(cp.get_pipeline_state(name=name), "Deploy")
    assert unaffected_state["latestExecution"]["pipelineExecutionId"] == execution_id_2, (
        "the rejected retry must not change the stage's recorded latest execution"
    )

    deploy_execs_before = _count_deploy_action_executions(cp, name, execution_id_2)

    retry_resp = cp.retry_stage_execution(
        pipelineName=name,
        stageName="Deploy",
        pipelineExecutionId=execution_id_2,
        retryMode="ALL_ACTIONS",
    )
    assert retry_resp["pipelineExecutionId"] == execution_id_2, (
        f"expected retrying the actual latest execution to succeed and echo "
        f"{execution_id_2!r}, got {retry_resp['pipelineExecutionId']!r}"
    )

    # Independent read at a different operation (ListActionExecutions, not the
    # RetryStageExecution response itself): the retry must actually have driven a new
    # Deploy action attempt, not merely been accepted.
    deploy_execs_after = _poll_until(
        lambda: _count_deploy_action_executions(cp, name, execution_id_2),
        lambda n: n > deploy_execs_before,
        timeout_s=45.0,
        interval_s=1.5,
    )
    assert deploy_execs_after > deploy_execs_before, (
        f"expected a new Deploy action execution after the accepted retry of "
        f"{execution_id_2!r}, count stayed at {deploy_execs_before}"
    )


# ===== helpers =====


def _get_execution_status_tolerant(cp, name: str, execution_id: str):
    try:
        return cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ]["status"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
            return None
        raise


def _run_to_terminal(cp, name: str, expected_status: str) -> str:
    resp = _start_execution_with_backoff(cp, name)
    execution_id = resp["pipelineExecutionId"]
    status = _poll_until(
        lambda: _get_execution_status_tolerant(cp, name, execution_id),
        lambda s: s in ("Succeeded", "Failed", "Stopped", "Superseded"),
        timeout_s=45.0,
        interval_s=1.5,
    )
    assert status == expected_status, f"execution {execution_id}: expected {expected_status!r}, got {status!r}"
    return execution_id


def _count_deploy_action_executions(cp, name: str, execution_id: str) -> int:
    resp = cp.list_action_executions(pipelineName=name, filter={"pipelineExecutionId": execution_id})
    return sum(
        1
        for a in resp.get("actionExecutionDetails", [])
        if a.get("stageName") == "Deploy" and a.get("actionName") == "Deploy"
    )


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    """IAM role propagation is real: CreatePipeline can transiently report the role as
    unassumable. Retry only that specific transient, never a structural rejection."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=declaration)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _delete_pipeline(cp, name):
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


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


def _create_bucket(ctx, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-")
    # S3 rejects an explicit LocationConstraint for us-east-1 (API quirk, not a region
    # pin of this check -- the check itself runs wherever ctx.region says).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    if versioned:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

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
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
