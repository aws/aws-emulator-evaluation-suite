"""approval-rejection-records-the-reviewer-and-withholds-the-downstream-stage."""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "approval-rejection-records-the-reviewer-and-withholds-the-downstream-stage"
GROUP = "state-machine"
SERVICES = ["codepipeline"]

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = "codepipeline-approval-rejection-reviewer"


@tags("axis:negative-delivery", "cap:c4", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A rejected manual approval fails its stage, records the reviewer's summary and identity,
    and the downstream Deploy stage never runs, while an identical approved pipeline deploys.

    Reference: https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PutApprovalResult.html
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    create_timeout_s = 240
    run_timeout_s = 300

    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    reviewer = caller_arn.rsplit("/", 1)[-1]
    assert reviewer, f"could not derive a reviewer identity from caller ARN {caller_arn!r}"

    bucket = _artifact_bucket(ctx, s3)
    source_bytes = _zip({"payload.bin": os.urandom(2048)})
    source_sha = _sha(source_bytes)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=source_bytes)
    role_arn = _pipeline_role(ctx, bucket)

    rej_name = ctx.unique_name("sim2real-behav-cprej-")
    apr_name = ctx.unique_name("sim2real-behav-cpapr-")
    rej_key, apr_key = f"{rej_name}/out.zip", f"{apr_name}/out.zip"
    # Unique per run, so a target can only report these by having stored what was sent.
    rej_summary = f"sim2real rejected {ctx.unique_name('r-')}"
    apr_summary = f"sim2real approved {ctx.unique_name('a-')}"

    for name, obj_key in ((rej_name, rej_key), (apr_name, apr_key)):
        _create_with_role_propagation(
            cp, _pipeline(name, role_arn, bucket, obj_key), timeout_s=create_timeout_s)
        ctx.on_cleanup(lambda n=name: cp.delete_pipeline(name=n))

    rej_exec = _first_execution(cp, rej_name, timeout_s=run_timeout_s)
    apr_exec = _first_execution(cp, apr_name, timeout_s=run_timeout_s)
    ctx.on_cleanup(lambda: _abandon(cp, rej_name, rej_exec))
    ctx.on_cleanup(lambda: _abandon(cp, apr_name, apr_exec))

    rej_token = _approval_token(cp, rej_name, rej_exec, timeout_s=run_timeout_s)
    apr_token = _approval_token(cp, apr_name, apr_exec, timeout_s=run_timeout_s)

    # Before either verdict, neither downstream Deploy may have run: the approval gates both.
    for name, obj_key in ((rej_name, rej_key), (apr_name, apr_key)):
        assert _get_object(s3, bucket, obj_key) is None, (
            f"the Deploy stage of {name!r} sits behind an outstanding manual approval, so "
            f"{obj_key!r} must not exist before any ApprovalResult is submitted"
        )

    cp.put_approval_result(
        pipelineName=rej_name, stageName="Approve", actionName="Approve",
        result={"summary": rej_summary, "status": "Rejected"}, token=rej_token)
    cp.put_approval_result(
        pipelineName=apr_name, stageName="Approve", actionName="Approve",
        result={"summary": apr_summary, "status": "Approved"}, token=apr_token)

    apr_status = _await_terminal(cp, apr_name, apr_exec, timeout_s=run_timeout_s)
    assert apr_status == "Succeeded", (
        f"control: the APPROVED twin must run its downstream Deploy stage and Succeed, otherwise "
        f"the rejected pipeline proves nothing; execution {apr_exec} of {apr_name!r} expected "
        f"'Succeeded', got {apr_status!r}. Record: {_execution(cp, apr_name, apr_exec)!r}"
    )
    apr_body = _poll(lambda: _get_object(s3, bucket, apr_key), lambda b: b is not None,
                     timeout_s=run_timeout_s, interval_s=3,
                     what=f"the approved twin {apr_name!r} to deploy {apr_key!r}")
    assert _sha(apr_body) == source_sha, (
        f"control: the approved twin must deploy the source bytes; expected sha256 "
        f"{source_sha!r}, got {_sha(apr_body)!r}"
    )

    rej_status = _await_terminal(cp, rej_name, rej_exec, timeout_s=run_timeout_s)
    assert rej_status == "Failed", (
        f"a Rejected approval must fail the execution: {rej_exec} of {rej_name!r} expected "
        f"'Failed', got {rej_status!r}. An emulator that accepts PutApprovalResult and marks "
        f"everything Succeeded fails here. Record: {_execution(cp, rej_name, rej_exec)!r}"
    )
    rej_action = _action_state(cp, rej_name, "Approve", "Approve")
    rej_latest = rej_action["latestExecution"]
    assert rej_latest.get("status") == "Failed", (
        f"the rejected approval ACTION itself must report Failed, not merely the execution: "
        f"expected 'Failed', got {rej_latest.get('status')!r} in {rej_action!r}"
    )

    # lastUpdatedBy names the caller by the last '/'-separated segment of its ARN.
    assert rej_latest.get("summary") == rej_summary, (
        f"the reviewer's rejection summary must be retrievable verbatim from GetPipelineState: "
        f"expected {rej_summary!r}, got {rej_latest.get('summary')!r}. An emulator that accepts "
        f"the ApprovalResult and discards its summary fails here."
    )
    assert reviewer in (rej_latest.get("lastUpdatedBy") or ""), (
        f"the approval action must record who decided it: expected lastUpdatedBy to name "
        f"{reviewer!r} (derived from caller ARN {caller_arn!r}), got "
        f"{rej_latest.get('lastUpdatedBy')!r}"
    )
    apr_latest = _action_state(cp, apr_name, "Approve", "Approve")["latestExecution"]
    assert apr_latest.get("summary") == apr_summary, (
        f"the APPROVED twin's summary must round-trip too, so the rejection leg above cannot "
        f"pass by the target echoing one hardcoded string: expected {apr_summary!r}, got "
        f"{apr_latest.get('summary')!r}"
    )
    assert apr_latest.get("status") == "Succeeded", (
        f"the approved action must report Succeeded; got {apr_latest.get('status')!r}"
    )

    # rej_exec is terminal, so absence here needs no observation window.
    assert _get_object(s3, bucket, rej_key) is None, (
        f"execution {rej_exec} of {rej_name!r} was rejected at Approve and is now terminally "
        f"Failed, so its downstream Deploy stage must never have run and {rej_key!r} must not "
        f"exist. An orchestrator emulator that runs every stage regardless of the upstream "
        f"verdict fails exactly here."
    )
    deploy_exec_id = _stage_state(cp, rej_name, "Deploy").get("latestExecution", {}).get(
        "pipelineExecutionId")
    assert deploy_exec_id != rej_exec, (
        f"the Deploy stage of {rej_name!r} must not report the rejected execution as its "
        f"latestExecution: got pipelineExecutionId {deploy_exec_id!r}, which equals the rejected "
        f"execution {rej_exec!r}"
    )
    rej_deploy_records = [d for d in _action_executions(cp, rej_name, rej_exec)
                          if d.get("stageName") == "Deploy"]
    assert rej_deploy_records == [], (
        f"ListActionExecutions must report no Deploy action record for the rejected execution "
        f"{rej_exec}; got {rej_deploy_records!r}"
    )


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred(value); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed value {val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _zip(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry, body in entries.items():
            zf.writestr(entry, body)
    return buf.getvalue()


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _get_object(s3, bucket, key):
    """The object bytes, or None if absent."""
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404", "NotFound"):
            return None
        raise


def _purge_bucket(s3, bucket) -> None:
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


def _artifact_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-behav-cpappr-").lower()
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
    name = ctx.unique_name("sim2real-behav-cpappr-")
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
        RoleName=name, PolicyName="artifacts",
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
    """CreatePipeline, retried while it answers InvalidStructureException because the new role
    is still propagating and cannot yet be assumed."""
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


def _pipeline(name, role_arn, bucket, object_key):
    """Source(S3) -> Approve(Manual) -> Deploy(S3), so a stage sits downstream of the approval."""
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "executionMode": "QUEUED",
        "stages": [
            {"name": "Source", "actions": [{
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3",
                                 "version": "1"},
                "runOrder": 1,
                "configuration": {"S3Bucket": bucket, "S3ObjectKey": "source.zip",
                                  "PollForSourceChanges": "false"},
                "outputArtifacts": [{"name": "SourceOutput"}],
            }]},
            {"name": "Approve", "actions": [{
                "name": "Approve",
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual",
                                 "version": "1"},
                "runOrder": 1,
            }]},
            {"name": "Deploy", "actions": [{
                "name": "Deploy",
                "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "S3",
                                 "version": "1"},
                "runOrder": 1,
                "configuration": {"BucketName": bucket, "Extract": "false",
                                  "ObjectKey": object_key},
                "inputArtifacts": [{"name": "SourceOutput"}],
            }]},
        ],
    }


def _stage_state(cp, name, stage_name):
    """The named stage from GetPipelineState; raises if it is missing."""
    state = cp.get_pipeline_state(name=name)
    for stage in state.get("stageStates", []):
        if stage.get("stageName") == stage_name:
            return stage
    raise AssertionError(
        f"GetPipelineState for {name!r} must report a stage named {stage_name!r}; stageStates "
        f"were {[s.get('stageName') for s in state.get('stageStates', [])]!r}"
    )


def _action_state(cp, name, stage_name, action_name):
    for action in _stage_state(cp, name, stage_name).get("actionStates", []):
        if action.get("actionName") == action_name:
            assert "latestExecution" in action, (
                f"the {action_name!r} action of stage {stage_name!r} in {name!r} must report a "
                f"latestExecution; got {action!r}"
            )
            return action
    raise AssertionError(
        f"stage {stage_name!r} of {name!r} must report an action named {action_name!r}; found "
        f"{[a.get('actionName') for a in _stage_state(cp, name, stage_name).get('actionStates', [])]!r}"
    )


def _approval_token(cp, name, execution_id, *, timeout_s):
    """The manual approval token, bound to this execution so a stale token is never used."""
    def _token():
        # Only the stage's latestExecution carries pipelineExecutionId, not the action's, so the
        # execution is matched on the stage and the token read off the action.
        stage = _stage_state(cp, name, "Approve")
        if stage.get("latestExecution", {}).get("pipelineExecutionId") != execution_id:
            return None
        for action in stage.get("actionStates", []):
            if action.get("actionName") == "Approve":
                return action.get("latestExecution", {}).get("token")
        return None

    return _poll(_token, lambda t: bool(t), timeout_s=timeout_s, interval_s=5,
                 what=f"the manual approval action of {name!r} to issue a token for execution "
                      f"{execution_id}")


def _execution(cp, name, execution_id):
    return cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]


def _execution_status(cp, name, execution_id):
    try:
        return _execution(cp, name, execution_id)["status"]
    except ClientError:
        return None


def _await_terminal(cp, name, execution_id, *, timeout_s):
    return _poll(lambda: _execution_status(cp, name, execution_id),
                 lambda s: s in _TERMINAL, timeout_s=timeout_s, interval_s=5,
                 what=f"execution {execution_id} of {name!r} to reach a terminal status")


def _execution_ids(cp, name):
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _first_execution(cp, name, *, timeout_s):
    ids = _poll(lambda: _execution_ids(cp, name), lambda i: len(i) >= 1,
                timeout_s=timeout_s, interval_s=3,
                what=f"CreatePipeline to auto-start an execution of {name!r}")
    return ids[0]


def _action_executions(cp, name, execution_id):
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
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
