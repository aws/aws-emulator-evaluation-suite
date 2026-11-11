"""deploy-artifact-bytes-are-identical-to-the-source-object."""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-artifact-bytes-are-identical-to-the-source-object"
GROUP = 'artifact-integrity'
SERVICES = ['codepipeline']

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = 'codepipeline-deploy-artifact-bytes'


# ===== helpers =====

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
    """The target's account id, the same source on every target."""
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


def _create_with_role_propagation(cp, declaration, *, timeout_s, tags=None):
    """CreatePipeline validates that it can assume the role, so it answers
    InvalidStructureException while the freshly created role is still propagating. IAM exposes no
    condition to poll for that, so the bounded retry IS the wait -- there is no bare sleep
    standing in for it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kw = {"tags": tags} if tags else {}
            return cp.create_pipeline(pipeline=declaration, **kw)
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
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown",
        )
    except ClientError as exc:
        # An execution that already finished cannot be stopped, and one whose pipeline is gone
        # cannot be found: both leave nothing behind.
        if exc.response["Error"]["Code"] not in (
            "PipelineExecutionNotStoppableException",
            "PipelineExecutionNotFoundException",
            "PipelineNotFoundException",
            "DuplicatedStopRequestException",
        ):
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
    """A V2 S3-source to S3-deploy execution that reaches Succeeded leaves a deploy object with
    the same SHA-256 and length as the consumed source object, and the execution records that
    object's S3 version id as its artifact revision."""
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    create_timeout_s = 180
    run_timeout_s = 300

    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)

    # Random bodies, so a delivered artifact can only match by having actually been copied.
    source_bytes = _zip({"payload.bin": os.urandom(4096),
                         "note.txt": "sim2real codepipeline artifact identity probe\n"})
    source_sha = _sha(source_bytes)
    version_id = s3.put_object(Bucket=bucket, Key="source.zip",
                               Body=source_bytes)["VersionId"]

    name = ctx.unique_name("sim2real-behav-cpbytes-")
    _create_with_role_propagation(
        cp,
        _pipeline(name, role_arn, bucket,
                  [_source_stage(bucket, "source.zip"),
                   {"name": "Deploy",
                    "actions": [_deploy_action("Deploy", bucket, "deployed/out.zip")]}]),
        timeout_s=create_timeout_s,
        tags=[{"key": "sim2real", "value": _SCENARIO}])
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    execution_id = _first_execution(cp, name, timeout_s=run_timeout_s)
    ctx.on_cleanup(lambda: _abandon(cp, name, execution_id))
    status = _poll(lambda: _execution_status(cp, name, execution_id),
                   lambda s: s in _TERMINAL, timeout_s=run_timeout_s, interval_s=3)
    assert status == "Succeeded", (
        f"execution {execution_id} of {name!r} must reach Succeeded (S3 source fetch then S3 "
        f"deploy), got {status!r}; full record "
        f"{_execution(cp, name, execution_id)!r}"
    )

    deploy_action = _action_state(cp, name, "Deploy", "Deploy")
    assert deploy_action.get("latestExecution", {}).get("status") == "Succeeded", (
        f"the Deploy action itself must report Succeeded, not merely the execution: "
        f"{deploy_action!r}"
    )

    keys = _poll(lambda: _keys_under(s3, bucket, "deployed/"),
                 lambda k: "deployed/out.zip" in k, timeout_s=run_timeout_s, interval_s=3)
    assert keys == ["deployed/out.zip"], (
        f"the Deploy action must write exactly its configured object key; objects under "
        f"deployed/ are {keys!r}"
    )

    delivered = s3.get_object(Bucket=bucket, Key="deployed/out.zip")["Body"].read()
    assert _sha(delivered) == source_sha, (
        f"the delivered artifact is not the source bytes: delivered sha256 "
        f"{_sha(delivered)!r} != source sha256 {source_sha!r}. An emulator that reports "
        f"Succeeded and writes a placeholder object at the right key fails here."
    )
    assert len(delivered) == len(source_bytes), (
        f"the artifact length changed in transit: delivered {len(delivered)!r} bytes vs source "
        f"{len(source_bytes)!r} bytes"
    )

    revisions = _execution(cp, name, execution_id).get("artifactRevisions", [])
    assert [r.get("revisionId") for r in revisions] == [version_id], (
        f"the execution must record the S3 object version it consumed as its artifact "
        f"revision: artifactRevisions {revisions!r}, uploaded version {version_id!r}"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
