"""stopping-an-execution-leaves-no-deploy-artifact-and-a-restop-is-rejected."""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stopping-an-execution-leaves-no-deploy-artifact-and-a-restop-is-rejected"
GROUP = 'overly-permissive'
SERVICES = ['codepipeline']

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = 'codepipeline-stop-no-artifact'


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


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
    """An in-memory zip of the supplied entries, so the check owns the exact bytes it expects back."""
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
    role_arn = iam.create_role(
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
    )["Role"]["Arn"]
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
    return role_arn


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    """CreatePipeline answers InvalidStructureException while a fresh role is still propagating;
    IAM exposes no condition to poll for that, so a bounded retry is the wait."""
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
    """Execution ids, newest first, across all pages."""
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
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _keys_under(s3, bucket, prefix):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _first_execution(cp, name, *, timeout_s):
    """The execution CreatePipeline starts on its own."""
    ids = _poll(lambda: _execution_ids(cp, name), lambda i: len(i) >= 1,
                timeout_s=timeout_s, interval_s=3)
    assert ids, (
        f"CreatePipeline started no execution of {name!r} and ListPipelineExecutions is empty; "
        f"an emulator that accepts CreatePipeline without scheduling the source action fails here"
    )
    return ids[0]

def _stop_error(cp, name, execution_id, reason) -> tuple[str, str]:
    """The (code, message) StopPipelineExecution refuses with; an accepted stop raises."""
    try:
        resp = cp.stop_pipeline_execution(pipelineName=name, pipelineExecutionId=execution_id,
                                          abandon=True, reason=reason)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"StopPipelineExecution of {execution_id} was ACCEPTED: {resp!r}")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An execution abandoned at a disabled stage transition reaches Stopped, writes no deploy object,
    and refuses a re-stop; with the transition enabled, a new execution delivers the source bytes.
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    create_timeout_s = 180
    run_timeout_s = 300

    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    source_bytes = _zip({"payload.bin": os.urandom(1024)})
    source_sha = _sha(source_bytes)

    # Created before source.zip exists, so the execution CreatePipeline starts cannot deploy
    # while the transition is still enabled.
    name = ctx.unique_name("sim2real-behav-cpstopart-")
    _create_with_role_propagation(
        cp,
        _pipeline(name, role_arn, bucket,
                  [_source_stage(bucket, "source.zip"),
                   {"name": "Deploy",
                    "actions": [_deploy_action("Deploy", bucket, "deployed/out.zip")]}]),
        timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    warmup_id = _first_execution(cp, name, timeout_s=run_timeout_s)
    ctx.on_cleanup(lambda: _abandon(cp, name, warmup_id))
    _poll(lambda: _execution_status(cp, name, warmup_id), lambda s: s in _TERMINAL,
          timeout_s=run_timeout_s, interval_s=3)

    s3.put_object(Bucket=bucket, Key="source.zip", Body=source_bytes)
    cp.disable_stage_transition(pipelineName=name, stageName="Deploy",
                                transitionType="Inbound",
                                reason="sim2real stop-without-artifact probe")
    gated = _poll(lambda: _stage_state(cp, name, "Deploy").get("inboundTransitionState", {}),
                  lambda t: t.get("enabled") is False, timeout_s=run_timeout_s, interval_s=3)
    assert gated.get("enabled") is False, (
        f"the Deploy stage's inbound transition must be disabled before the execution starts, "
        f"got {gated!r}"
    )

    held_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    ctx.on_cleanup(lambda: _abandon(cp, name, held_id))
    source_state = _poll(
        lambda: _stage_state(cp, name, "Source").get("latestExecution", {}),
        lambda e: e.get("pipelineExecutionId") == held_id and e.get("status") == "Succeeded",
        timeout_s=run_timeout_s, interval_s=3)
    assert (source_state.get("pipelineExecutionId"), source_state.get("status")) \
        == (held_id, "Succeeded"), (
        f"the Source stage never Succeeded for execution {held_id}, so the stop below would be "
        f"refused for being early rather than for being a re-stop: {source_state!r}"
    )
    assert _execution_status(cp, name, held_id) == "InProgress", (
        f"execution {held_id} must be InProgress at the held Deploy boundary before it is "
        f"stopped, got {_execution_status(cp, name, held_id)!r}"
    )

    # Stop only once held at Deploy: an earlier stop is refused with the same code as a re-stop.
    first_stop = cp.stop_pipeline_execution(pipelineName=name, pipelineExecutionId=held_id,
                                            abandon=True,
                                            reason="sim2real abandon the held execution")
    assert first_stop["pipelineExecutionId"] == held_id, (
        f"StopPipelineExecution must echo the stopped execution {held_id}, got {first_stop!r}"
    )
    stopped = _poll(lambda: _execution_status(cp, name, held_id), lambda s: s in _TERMINAL,
                    timeout_s=run_timeout_s, interval_s=3)
    assert stopped == "Stopped", (
        f"an abandoned execution must reach the terminal status Stopped specifically, got "
        f"{stopped!r}"
    )

    abandoned_keys = _keys_under(s3, bucket, "deployed/")
    assert abandoned_keys == [], (
        f"the abandoned execution still delivered an artifact: objects under deployed/ are "
        f"{abandoned_keys!r}. An emulator that flips an execution to Stopped after having "
        f"already run the downstream action fails here."
    )

    restop, restop_message = _stop_error(cp, name, held_id, "sim2real re-stop a terminal execution")
    assert restop == "PipelineExecutionNotStoppableException", (
        f"stopping the already-Stopped execution {held_id} was not refused with "
        f"PipelineExecutionNotStoppableException: got {restop!r}"
    )
    expected = (
        f"The pipeline execution with ID '{held_id}' in '{name}' can't be stopped now. Either it "
        "does not exist in the pipeline, or the pipeline execution has no action executions in "
        "progress."
    )
    assert restop_message == expected, f"expected message {expected!r}, got {restop_message!r}"
    assert _execution_status(cp, name, held_id) == "Stopped", (
        f"the refused re-stop rewrote the terminal status of {held_id}: "
        f"{_execution_status(cp, name, held_id)!r}"
    )

    cp.enable_stage_transition(pipelineName=name, stageName="Deploy",
                               transitionType="Inbound")
    control_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    ctx.on_cleanup(lambda: _abandon(cp, name, control_id))
    control_status = _poll(lambda: _execution_status(cp, name, control_id),
                           lambda s: s in _TERMINAL, timeout_s=run_timeout_s, interval_s=3)
    assert control_status == "Succeeded", (
        f"the control execution {control_id} must Succeed, otherwise the absence asserted above "
        f"is not evidence of anything: {control_status!r}, full record "
        f"{_execution(cp, name, control_id)!r}"
    )
    _poll(lambda: _keys_under(s3, bucket, "deployed/"), lambda k: "deployed/out.zip" in k,
          timeout_s=run_timeout_s, interval_s=3)
    control_sha = _sha(s3.get_object(Bucket=bucket, Key="deployed/out.zip")["Body"].read())
    assert control_sha == source_sha, (
        f"the control execution did not deliver the source bytes ({control_sha!r} != "
        f"{source_sha!r}), so this pipeline never delivers and the effect-absent assertion "
        f"above proves nothing"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
