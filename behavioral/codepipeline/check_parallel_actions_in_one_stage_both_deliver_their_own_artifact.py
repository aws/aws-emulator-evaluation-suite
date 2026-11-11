"""parallel-actions-in-one-stage-both-deliver-their-own-artifact."""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "parallel-actions-in-one-stage-both-deliver-their-own-artifact"
GROUP = 'artifact-integrity'
SERVICES = ['codepipeline']

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = 'codepipeline-parallel-actions'


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
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
    """An in-memory zip of the supplied entries, so the check owns the exact delivered bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry, body in entries.items():
            zf.writestr(entry, body)
    return buf.getvalue()


def _artifact_bucket(ctx) -> str:
    """A versioned, tagged artifact store bucket."""
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
    """Retry CreatePipeline while it answers InvalidStructureException for a still-propagating
    role; IAM exposes no condition to poll, so the bounded retry is the wait."""
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
    """A V2 pipeline declaration; stages here are S3 source and S3 deploy only."""
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
    """CreatePipeline starts an execution of its own; that is the execution these checks grade,
    so there is no StartPipelineExecution to race it."""
    ids = _poll(lambda: _execution_ids(cp, name), lambda i: len(i) >= 1,
                timeout_s=timeout_s, interval_s=3)
    assert ids, (
        f"CreatePipeline started no execution of {name!r} and ListPipelineExecutions is empty; "
        f"an emulator that accepts CreatePipeline without scheduling the source action fails here"
    )
    return ids[0]


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Two deploy actions sharing a runOrder in one stage both run in the single execution, each
    delivering its own byte-correct object, recorded under the same pipelineExecutionId.
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    create_timeout_s = 180
    run_timeout_s = 300

    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    source_bytes = _zip({"payload.bin": os.urandom(2048)})
    source_sha = _sha(source_bytes)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=source_bytes)

    name = ctx.unique_name("sim2real-behav-cppar-")
    _create_with_role_propagation(
        cp,
        _pipeline(name, role_arn, bucket,
                  [_source_stage(bucket, "source.zip"),
                   {"name": "Deploy",
                    "actions": [_deploy_action("DeployA", bucket, "a/out.zip"),
                                _deploy_action("DeployB", bucket, "b/out.zip")]}]),
        timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    execution_id = _first_execution(cp, name, timeout_s=run_timeout_s)
    ctx.on_cleanup(lambda: _abandon(cp, name, execution_id))
    status = _poll(lambda: _execution_status(cp, name, execution_id),
                   lambda s: s in _TERMINAL, timeout_s=run_timeout_s, interval_s=3)
    assert status == "Succeeded", (
        f"execution {execution_id} of {name!r} must reach Succeeded, got {status!r}; full "
        f"record {_execution(cp, name, execution_id)!r}"
    )

    keys = _poll(lambda: _keys_under(s3, bucket, "a/") + _keys_under(s3, bucket, "b/"),
                 lambda k: len(k) >= 2, timeout_s=run_timeout_s, interval_s=3)
    assert keys == ["a/out.zip", "b/out.zip"], (
        f"both parallel deploy actions must write their own object: found {keys!r}. An emulator "
        f"that runs only the first action of a runOrder group fails here."
    )
    digests = {k: _sha(s3.get_object(Bucket=bucket, Key=k)["Body"].read()) for k in keys}
    assert set(digests.values()) == {source_sha}, (
        f"a parallel action delivered the wrong bytes: {digests!r}, source sha256 {source_sha!r}"
    )

    deploys = {d["actionName"]: d for d in _action_executions(cp, name, execution_id)
               if d.get("stageName") == "Deploy"}
    assert sorted(deploys) == ["DeployA", "DeployB"], (
        f"both parallel actions must be recorded as action executions of {execution_id}: "
        f"{sorted(deploys)!r}"
    )
    assert [deploys[a]["status"] for a in ("DeployA", "DeployB")] == \
        ["Succeeded", "Succeeded"], (
        f"a parallel action did not Succeed: "
        f"{ {a: deploys[a]['status'] for a in deploys} !r}"
    )
    assert {deploys[a]["pipelineExecutionId"] for a in deploys} == {execution_id}, (
        f"the two actions were not recorded under the one pipeline execution: "
        f"{ {a: deploys[a]['pipelineExecutionId'] for a in deploys} !r} vs {execution_id!r}"
    )
    assert deploys["DeployA"]["actionExecutionId"] != deploys["DeployB"]["actionExecutionId"], (
        f"the two parallel actions share one actionExecutionId, so only one action really ran: "
        f"{ {a: deploys[a]['actionExecutionId'] for a in deploys} !r}"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
