"""approval-gate-withholds-the-artifact-until-it-is-approved."""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "approval-gate-withholds-the-artifact-until-it-is-approved"
GROUP = 'state-machine'
SERVICES = ['codepipeline']

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = 'codepipeline-approval-withholds-artifact'


# ===== helpers =====

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, fn, pred, *, timeout_s, interval_s):
    """The first fn() value pred accepts, else the last one once the capped deadline passes; a
    wait the run budget ended raises TimeoutError instead."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("a wait outlived the run budget; not graded")
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _account_id(ctx) -> str:
    return ctx.account


def _purge_bucket(s3, bucket) -> None:
    """Every execution writes a new version of the artifact into the store; a versioned bucket
    needs version-aware deletion or DeleteBucket fails."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _zip(entries) -> bytes:
    """A deterministic archive of the supplied entries, built in memory so the check owns the
    exact bytes it later demands back out of the artifact store."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry, body in entries.items():
            zf.writestr(entry, body)
    return buf.getvalue()


def _artifact_bucket(ctx) -> str:
    """A tagged, versioned S3 artifact store."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cp-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _pipeline_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cp-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="artifacts",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                           "s3:GetBucketVersioning", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"))
    return f"arn:aws:iam::{_account_id(ctx)}:role/{name}"


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    """CreatePipeline validates that it can assume the role, so it answers
    InvalidStructureException while the freshly created role is still propagating. IAM exposes no
    condition to poll for that, so the bounded retry IS the wait -- there is no bare sleep
    standing in for it."""
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


def _source_stage(bucket, key, *, namespace=None):
    action = {
        "name": "Source",
        "actionTypeId": {"category": "Source", "owner": "AWS",
                         "provider": "S3", "version": "1"},
        "runOrder": 1,
        "configuration": {"S3Bucket": bucket, "S3ObjectKey": key,
                          "PollForSourceChanges": "false"},
        "outputArtifacts": [{"name": "SourceOutput"}],
    }
    if namespace:
        action["namespace"] = namespace
    return {"name": "Source", "actions": [action]}


def _deploy_action(action_name, bucket, object_key, *, extract="false"):
    return {
        "name": action_name,
        "actionTypeId": {"category": "Deploy", "owner": "AWS",
                         "provider": "S3", "version": "1"},
        "runOrder": 1,
        "configuration": {"BucketName": bucket, "Extract": extract,
                          "ObjectKey": object_key},
        "inputArtifacts": [{"name": "SourceOutput"}],
    }


def _pipeline(name, role_arn, bucket, stages, *, execution_mode="QUEUED"):
    """Source(S3) -> Deploy(S3) only. Both actions are a small object fetch and a small object
    write inside the same bucket, so an execution here cannot start a CodeBuild build, a
    CodeDeploy deployment or a CloudFormation stack."""
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "executionMode": execution_mode,
        "stages": stages,
    }


def _stage_state(cp, name, stage_name):
    for stage in cp.get_pipeline_state(name=name).get("stageStates", []):
        if stage.get("stageName") == stage_name:
            return stage
    return {}


def _action_state(cp, name, stage_name, action_name):
    for action in _stage_state(cp, name, stage_name).get("actionStates", []):
        if action.get("actionName") == action_name:
            return action
    return {}


def _execution(cp, name, execution_id):
    return cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]


def _execution_status(cp, name, execution_id):
    try:
        return _execution(cp, name, execution_id)["status"]
    except ClientError:
        return None


def _execution_ids(cp, name):
    """Newest-first per the operation's contract, paginated because an account can
    hold more executions than one page."""
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _action_executions(cp, name, execution_id):
    """ActionExecutionDetail records for one execution, paginated on nextToken."""
    out, token = [], None
    while True:
        kw = {"pipelineName": name, "filter": {"pipelineExecutionId": execution_id}}
        if token:
            kw["nextToken"] = token
        page = cp.list_action_executions(**kw)
        out.extend(page.get("actionExecutionDetails", []))
        token = page.get("nextToken")
        if not token:
            return out


def _abandon(cp, name, execution_id):
    try:
        status = cp.get_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id
        )["pipelineExecution"]["status"]
        if status in ("Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"):
            return
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "PipelineNotFoundException", "PipelineExecutionNotFoundException"
        ):
            raise


def _keys_under(s3, bucket, prefix):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _first_execution(ctx, cp, name, *, timeout_s):
    """CreatePipeline starts an execution of its own; that is the execution these checks grade,
    so there is no StartPipelineExecution to race it."""
    ids = _poll(ctx, lambda: _execution_ids(cp, name), lambda i: len(i) >= 1,
                timeout_s=timeout_s, interval_s=2)
    assert ids, (
        f"CreatePipeline started no execution of {name!r} and ListPipelineExecutions is empty; "
        f"an emulator that accepts CreatePipeline without scheduling the source action fails here"
    )
    return ids[0]


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """While a Manual approval is pending the gated pipeline's deploy object is absent from S3 after
    an identical ungated pipeline has delivered; the deploy action starts no earlier than
    PutApprovalResult(Approved) and delivers the source bytes intact."""
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    create_timeout_s = 180
    run_timeout_s = 300

    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    source_bytes = _zip({"payload.bin": os.urandom(1024)})
    source_sha = _sha(source_bytes)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=source_bytes)

    control_name = ctx.unique_name("sim2real-behav-cpctl-")
    _create_with_role_propagation(
        cp,
        _pipeline(control_name, role_arn, bucket,
                  [_source_stage(bucket, "source.zip"),
                   {"name": "Deploy",
                    "actions": [_deploy_action("Deploy", bucket, "control/out.zip")]}]),
        timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=control_name))

    gated_name = ctx.unique_name("sim2real-behav-cpgate-")
    _create_with_role_propagation(
        cp,
        _pipeline(gated_name, role_arn, bucket,
                  [_source_stage(bucket, "source.zip"),
                   {"name": "Approve",
                    "actions": [{"name": "Approve",
                                 "actionTypeId": {"category": "Approval", "owner": "AWS",
                                                  "provider": "Manual", "version": "1"},
                                 "runOrder": 1}]},
                   {"name": "Deploy",
                    "actions": [_deploy_action("Deploy", bucket, "gated/out.zip")]}]),
        timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=gated_name))

    # Both pipelines start an execution of their own at create and run concurrently, so the
    # control's delivery is the positive control the gated pipeline's absence is read against.
    control_id = _first_execution(ctx, cp, control_name, timeout_s=run_timeout_s)
    ctx.on_cleanup(lambda: _abandon(cp, control_name, control_id))
    gated_id = _first_execution(ctx, cp, gated_name, timeout_s=run_timeout_s)
    ctx.on_cleanup(lambda: _abandon(cp, gated_name, gated_id))

    control_status = _poll(ctx, lambda: _execution_status(cp, control_name, control_id),
                           lambda s: s in _TERMINAL, timeout_s=run_timeout_s, interval_s=2)
    assert control_status == "Succeeded", (
        f"the ungated control pipeline must Succeed, otherwise an empty gated prefix is not "
        f"evidence of anything: {control_status!r}, full record "
        f"{_execution(cp, control_name, control_id)!r}"
    )
    _poll(ctx, lambda: _keys_under(s3, bucket, "control/"), lambda k: "control/out.zip" in k,
          timeout_s=run_timeout_s, interval_s=2)
    control_sha = _sha(s3.get_object(Bucket=bucket, Key="control/out.zip")["Body"].read())
    assert control_sha == source_sha, (
        f"the control pipeline delivered the wrong bytes ({control_sha!r} != {source_sha!r}), so "
        f"delivery is not proven prompt and the absence below proves nothing"
    )

    approval = _poll(
        ctx,
        lambda: _action_state(cp, gated_name, "Approve", "Approve").get("latestExecution", {}),
        lambda e: bool(e.get("token")), timeout_s=run_timeout_s, interval_s=2)
    token = approval.get("token")
    assert token, (
        f"no approval token was ever surfaced for the gated execution {gated_id}: {approval!r}"
    )

    gated_keys = _keys_under(s3, bucket, "gated/")
    assert gated_keys == [], (
        f"the artifact was delivered before the approval was granted: {gated_keys!r}, although "
        f"the ungated control has already delivered. An emulator that treats a Manual approval "
        f"action as a no-op fails here."
    )
    still_pending = _action_state(cp, gated_name, "Approve", "Approve").get("latestExecution", {})
    assert still_pending.get("status") == "InProgress", (
        f"the approval action is not InProgress, so the empty gated prefix above may only mean the "
        f"execution died: {still_pending!r}, execution status "
        f"{_execution_status(cp, gated_name, gated_id)!r}"
    )

    approved_at = cp.put_approval_result(
        pipelineName=gated_name, stageName="Approve", actionName="Approve", token=token,
        result={"summary": "sim2real behavioral approval", "status": "Approved"})["approvedAt"]
    gated_status = _poll(ctx, lambda: _execution_status(cp, gated_name, gated_id),
                         lambda s: s in _TERMINAL, timeout_s=run_timeout_s, interval_s=2)
    assert gated_status == "Succeeded", (
        f"the approved execution {gated_id} must Succeed, got {gated_status!r}; full record "
        f"{_execution(cp, gated_name, gated_id)!r}"
    )
    _poll(ctx, lambda: _keys_under(s3, bucket, "gated/"), lambda k: "gated/out.zip" in k,
          timeout_s=run_timeout_s, interval_s=2)
    gated_sha = _sha(s3.get_object(Bucket=bucket, Key="gated/out.zip")["Body"].read())
    assert gated_sha == source_sha, (
        f"approval did not release the source artifact: {gated_sha!r} != {source_sha!r}"
    )
    deploys = [d for d in _action_executions(cp, gated_name, gated_id)
               if d.get("stageName") == "Deploy" and d.get("actionName") == "Deploy"]
    assert len(deploys) == 1, (
        f"the approved execution {gated_id} must run its Deploy action once: {deploys!r}"
    )
    assert deploys[0]["startTime"] >= approved_at, (
        f"the gated Deploy action started at {deploys[0]['startTime']!r}, before the approval "
        f"granted at {approved_at!r}"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
