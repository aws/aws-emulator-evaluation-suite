"""put-approval-result-stale-token-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-approval-result-stale-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutApprovalResult with a token other than the outstanding one fails with InvalidApprovalTokenException and
    its exact message, leaving the approval InProgress, while the real token then approves it and the
    execution Succeeds.
    """
    cp = ctx.client("codepipeline")
    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    _upload_source_zip(ctx, bucket, "source/source.zip")

    pipeline_name = ctx.unique_name("sim2real-cp-badtok-")
    stages = [_source_stage(bucket, "source/source.zip"), _approval_stage()]
    _create_pipeline(ctx, pipeline_name, role_arn, bucket, stages)

    # CreatePipeline with a real Source action starts an execution of its own; a second,
    # explicit StartPipelineExecution here would race it under the pipeline's default
    # SUPERSEDED execution mode -- the token grabbed below could then belong to whichever
    # execution reaches the Approve stage first, while the id tracked for the terminal read
    # belongs to the OTHER one, which never gets approved and never leaves InProgress.
    execution_id = _wait_for_single_execution(ctx, pipeline_name)
    real_token = _wait_for_approval_token(ctx, pipeline_name)

    wrong_token = real_token[:-1] + ("0" if real_token[-1] != "0" else "1") if real_token[-1:] else "bogus"
    code, message = _error_code(
        lambda: cp.put_approval_result(
            pipelineName=pipeline_name,
            stageName="Approve",
            actionName="ApprovalAction",
            result={"summary": "wrong token", "status": "Approved"},
            token=wrong_token,
        )
    )
    assert (code, message) == (
        "InvalidApprovalTokenException",
        # AWS wraps the token in U+2018/U+2019 curly quotes.
        f"Approval token \u2018{wrong_token}\u2019 either does not exist or is not the correct "
        "token for action ApprovalAction and stage Approve.",
    ), (
        f"unexpected refusal for wrong token: {(code, message)!r}"
    )

    # effect absent: approval action still pending, not advanced
    state_after_bad = cp.get_pipeline_state(name=pipeline_name)
    approve_after_bad = next(s for s in state_after_bad["stageStates"] if s["stageName"] == "Approve")
    action_after_bad = next(
        a for a in approve_after_bad["actionStates"] if a["actionName"] == "ApprovalAction"
    )
    assert action_after_bad["latestExecution"]["status"] == "InProgress", (
        f"approval action advanced despite rejected token: {action_after_bad['latestExecution']}"
    )

    # positive control: the real token succeeds and the execution completes
    cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName="Approve",
        actionName="ApprovalAction",
        result={"summary": "real token", "status": "Approved"},
        token=real_token,
    )
    execution = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ],
        lambda ex: ex["status"] in ("Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert execution["status"] == "Succeeded", f"positive control did not succeed: {execution}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-")
    kwargs = {"Bucket": bucket}
    # CreateBucket rejects an explicit LocationConstraint that names the caller's own region when
    # that region is us-east-1 -- this branches on the S3 API quirk, not a hardcoded target region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket) -> None:
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
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _upload_source_zip(ctx, bucket, key) -> None:
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral fixture\n")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _pipeline_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:GetBucketVersioning", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-inline"))
    return role_arn


def _source_stage(bucket, key):
    return {
        "name": "Source",
        "actions": [
            {
                "name": "SourceAction",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
            }
        ],
    }


def _approval_stage():
    return {
        "name": "Approve",
        "actions": [
            {
                "name": "ApprovalAction",
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
            }
        ],
    }


def _create_pipeline(ctx, name, role_arn, bucket, stages, timeout_s=60.0):
    cp = ctx.client("codepipeline")
    decl = {"name": name, "roleArn": role_arn, "artifactStore": {"type": "S3", "location": bucket}, "stages": stages}
    tags = [{"key": "sim2real", "value": name}]
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = cp.create_pipeline(pipeline=decl, tags=tags)
            ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
            return resp["pipeline"]
        except Exception as exc:  # IAM role/trust propagation is eventually consistent
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreatePipeline never succeeded: {last_err}")


def _wait_for_single_execution(ctx, pipeline_name, timeout_s=60.0):
    cp = ctx.client("codepipeline")

    def probe():
        return cp.list_pipeline_executions(pipelineName=pipeline_name).get(
            "pipelineExecutionSummaries", []
        )

    summaries = _poll_until(probe, lambda s: len(s) >= 1, timeout_s=timeout_s, interval_s=3.0)
    assert len(summaries) == 1, (
        f"expected exactly one execution auto-started by CreatePipeline, got "
        f"{[s['pipelineExecutionId'] for s in summaries]}"
    )
    return summaries[0]["pipelineExecutionId"]


def _wait_for_approval_token(ctx, pipeline_name, timeout_s=60.0):
    cp = ctx.client("codepipeline")

    def probe():
        state = cp.get_pipeline_state(name=pipeline_name)
        approve = next((s for s in state["stageStates"] if s["stageName"] == "Approve"), None)
        if not approve:
            return None
        action = next((a for a in approve.get("actionStates", []) if a["actionName"] == "ApprovalAction"), None)
        if not action:
            return None
        return action.get("latestExecution", {}).get("token")

    return _poll_until(probe, lambda t: t is not None, timeout_s=timeout_s, interval_s=3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
