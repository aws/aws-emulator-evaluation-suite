"""disabled-transition-withhold-is-bounded-by-a-concurrent-enabled-twin."""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disabled-transition-withhold-is-bounded-by-a-concurrent-enabled-twin"
GROUP = "state-machine"
SERVICES = ["codepipeline"]

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = "codepipeline-transition-twin-control"
_WITHHOLD_WINDOW_S = 15.0


@tags("axis:negative-delivery", "cap:c4", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A disabled Deploy inbound transition withholds the artifact for 15s after a concurrent
    enabled twin pipeline delivered it; enabling it then delivers the held execution's artifact
    byte-identically and the execution Succeeds.
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    create_timeout_s = 240
    run_timeout_s = 300

    bucket = _artifact_bucket(ctx, s3)
    source_bytes = _zip({"payload.bin": os.urandom(2048),
                         "note.txt": "sim2real codepipeline twin-control withhold probe\n"})
    source_sha = _sha(source_bytes)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=source_bytes)
    role_arn = _pipeline_role(ctx, bucket)

    held_name = ctx.unique_name("sim2real-behav-cpheld-")
    twin_name = ctx.unique_name("sim2real-behav-cptwin-")
    held_key, twin_key = "deployed/held.zip", "deployed/twin.zip"

    for name, obj_key in ((held_name, held_key), (twin_name, twin_key)):
        _create_with_role_propagation(
            ctx, cp, _pipeline(name, role_arn, bucket, obj_key),
            timeout_s=_budget_s(ctx, create_timeout_s))
        ctx.on_cleanup(lambda n=name: cp.delete_pipeline(name=n))

    # Disable before the graded executions start, and abandon the auto-started executions so
    # none is already past the boundary.
    reason = "sim2real behavioral twin-control withhold"
    cp.disable_stage_transition(pipelineName=held_name, stageName="Deploy",
                                transitionType="Inbound", reason=reason)
    ctx.on_cleanup(lambda: _enable_quietly(cp, held_name))

    for name in (held_name, twin_name):
        for exec_id in _execution_ids(cp, name):
            _abandon(cp, name, exec_id)
        _poll(ctx, lambda n=name: [_execution_status(cp, n, e) for e in _execution_ids(cp, n)],
              lambda sts: all(s in _TERMINAL for s in sts),
              timeout_s=_budget_s(ctx, run_timeout_s), interval_s=1,
              what=f"the auto-started execution(s) of {name!r} to reach a terminal state")

    for key in (held_key, twin_key):
        _delete_if_present(s3, bucket, key)
    _poll(ctx, lambda: [_get_object(s3, bucket, k) for k in (held_key, twin_key)],
          lambda bodies: all(b is None for b in bodies),
          timeout_s=_budget_s(ctx, 120), interval_s=1,
          what="both deploy objects to be absent before the graded executions start")

    assert _inbound_enabled(cp, held_name, "Deploy") is False, (
        f"DisableStageTransition must be in effect before the graded executions start: "
        f"GetPipelineState reports Deploy.inboundTransitionState.enabled "
        f"{_inbound_enabled(cp, held_name, 'Deploy')!r} for {held_name!r}, expected False"
    )
    assert _inbound_enabled(cp, twin_name, "Deploy") is not False, (
        f"the twin's Deploy transition must NOT be disabled -- it is the control: got enabled "
        f"{_inbound_enabled(cp, twin_name, 'Deploy')!r} for {twin_name!r}"
    )

    # ---- both executions start in the same instant ----
    held_exec = cp.start_pipeline_execution(name=held_name)["pipelineExecutionId"]
    twin_exec = cp.start_pipeline_execution(name=twin_name)["pipelineExecutionId"]
    ctx.on_cleanup(lambda: _abandon(cp, held_name, held_exec))
    ctx.on_cleanup(lambda: _abandon(cp, twin_name, twin_exec))
    started = time.monotonic()

    # ---- the twin delivers on this exact wiring, at this exact moment ----
    twin_body = _poll(ctx, lambda: _get_object(s3, bucket, twin_key), lambda b: b is not None,
                      timeout_s=_budget_s(ctx, run_timeout_s), interval_s=1,
                      what=f"the transition-ENABLED twin {twin_name!r} to deliver {twin_key!r}; "
                           f"if this times out the control is broken and the withhold below "
                           f"would prove nothing")
    latency_s = time.monotonic() - started
    assert _sha(twin_body) == source_sha, (
        f"the twin control must deliver the source bytes; expected sha256 {source_sha!r}, got "
        f"{_sha(twin_body)!r}"
    )
    twin_status = _await_terminal(ctx, cp, twin_name, twin_exec,
                                  timeout_s=_budget_s(ctx, run_timeout_s))
    assert twin_status == "Succeeded", (
        f"twin control execution {twin_exec} of {twin_name!r} must Succeed; expected "
        f"'Succeeded', got {twin_status!r}"
    )

    # ---- absence, held for a fixed window after the twin delivered the identical work ----
    window_s = _WITHHOLD_WINDOW_S
    deadline = time.monotonic() + window_s
    while True:
        held_body = _get_object(s3, bucket, held_key)
        assert held_body is None, (
            f"the Deploy stage's inbound transition is disabled on {held_name!r}, so execution "
            f"{held_exec} must not deliver {held_key!r}; found {len(held_body)} bytes after "
            f"{time.monotonic() - (deadline - window_s):.0f}s of a {window_s:.0f}s window "
            f"(the twin delivered in {latency_s:.0f}s). An emulator that accepts "
            f"DisableStageTransition and ignores it fails here."
        )
        deploy_exec_id = _stage_latest_execution_id(cp, held_name, "Deploy")
        assert deploy_exec_id != held_exec, (
            f"Deploy's latestExecution must not be bound to the withheld execution: "
            f"GetPipelineState reports pipelineExecutionId {deploy_exec_id!r} on {held_name!r}, "
            f"which equals the held execution {held_exec!r}"
        )
        still_disabled = _inbound_enabled(cp, held_name, "Deploy")
        assert still_disabled is False, (
            f"the transition must stay disabled for the whole window -- a target that quietly "
            f"re-enables it would otherwise look like it withheld: expected enabled False, got "
            f"{still_disabled!r} on {held_name!r}"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(max(0.0, min(1.0, deadline - time.monotonic())))

    held_status = _execution_status(cp, held_name, held_exec)
    assert held_status == "InProgress", (
        f"the withheld execution must still be InProgress at the transition boundary, not "
        f"terminal: execution {held_exec} of {held_name!r} expected 'InProgress', got "
        f"{held_status!r}. A target that FAILS the execution instead of holding it also fails "
        f"the release leg below, but this names the divergence precisely."
    )

    # ---- release: re-enable the transition and demand the delivery ----
    cp.enable_stage_transition(pipelineName=held_name, stageName="Deploy",
                               transitionType="Inbound")
    held_delivered = _poll(
        ctx, lambda: _get_object(s3, bucket, held_key), lambda b: b is not None,
        timeout_s=_budget_s(ctx, run_timeout_s), interval_s=1,
        what=f"EnableStageTransition to release the withheld artifact {held_key!r} (the twin "
             f"needed {latency_s:.0f}s for the identical work)")
    assert _sha(held_delivered) == source_sha, (
        f"the released artifact must be the same bytes the twin delivered: expected sha256 "
        f"{source_sha!r}, got {_sha(held_delivered)!r}"
    )
    released_status = _await_terminal(ctx, cp, held_name, held_exec,
                                      timeout_s=_budget_s(ctx, run_timeout_s))
    assert released_status == "Succeeded", (
        f"after EnableStageTransition the previously withheld execution {held_exec} of "
        f"{held_name!r} must reach Succeeded; expected 'Succeeded', got {released_status!r}. A "
        f"target that fakes the withhold by never delivering anything fails exactly here."
    )
    assert _stage_latest_execution_id(cp, held_name, "Deploy") == held_exec, (
        f"after release, Deploy's latestExecution must name the execution that was withheld: "
        f"expected {held_exec!r}, got {_stage_latest_execution_id(cp, held_name, 'Deploy')!r}"
    )



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred holds; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s:.0f}s waiting for {what}; last observed value {val!r}"
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


def _delete_if_present(s3, bucket, key) -> None:
    s3.delete_object(Bucket=bucket, Key=key)


def _purge_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


def _artifact_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-behav-cptwin-").lower()
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
    name = ctx.unique_name("sim2real-behav-cptwin-")
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


def _create_with_role_propagation(ctx, cp, declaration, *, timeout_s):
    """CreatePipeline, retried while it answers InvalidStructureException for a still-propagating
    role."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=declaration)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError("CreatePipeline past the role's propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)


def _pipeline(name, role_arn, bucket, object_key):
    """One declaration template: the held pipeline and the twin differ only in name and deploy key,
    so the twin is a like-for-like control for the held one."""
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
    """The named stage's GetPipelineState entry; fails if the stage is missing."""
    state = cp.get_pipeline_state(name=name)
    for stage in state.get("stageStates", []):
        if stage.get("stageName") == stage_name:
            return stage
    raise AssertionError(
        f"GetPipelineState for {name!r} must report a stage named {stage_name!r}; stageStates "
        f"were {[s.get('stageName') for s in state.get('stageStates', [])]!r}"
    )


def _inbound_enabled(cp, name, stage_name):
    """Deploy's inbound transition flag. Returns None when the service omits
    inboundTransitionState entirely, which callers distinguish from an explicit False."""
    return _stage_state(cp, name, stage_name).get("inboundTransitionState", {}).get("enabled")


def _stage_latest_execution_id(cp, name, stage_name):
    return _stage_state(cp, name, stage_name).get("latestExecution", {}).get(
        "pipelineExecutionId")


def _execution(cp, name, execution_id):
    return cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]


def _execution_status(cp, name, execution_id):
    try:
        return _execution(cp, name, execution_id)["status"]
    except ClientError:
        return None


def _await_terminal(ctx, cp, name, execution_id, *, timeout_s):
    return _poll(ctx, lambda: _execution_status(cp, name, execution_id),
                 lambda s: s in _TERMINAL, timeout_s=timeout_s, interval_s=1,
                 what=f"execution {execution_id} of {name!r} to reach a terminal status")


def _execution_ids(cp, name):
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _enable_quietly(cp, name) -> None:
    """Never leave this check's pipeline with a disabled transition."""
    try:
        cp.enable_stage_transition(pipelineName=name, stageName="Deploy",
                                   transitionType="Inbound")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("PipelineNotFoundException", "StageNotFoundException"):
            raise


def _abandon(cp, name, execution_id):
    try:
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown")
    except ClientError as e:
        # Already stopped, completed or gone: nothing left to abandon.
        if e.response["Error"]["Code"] not in (
                "PipelineExecutionNotStoppableException", "DuplicatedStopRequestException",
                "PipelineExecutionNotFoundException", "PipelineNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
