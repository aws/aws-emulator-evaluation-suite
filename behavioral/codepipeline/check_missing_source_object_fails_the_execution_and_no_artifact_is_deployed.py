"""missing-source-object-fails-the-execution-and-no-artifact-is-deployed."""
from __future__ import annotations

import hashlib
import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "missing-source-object-fails-the-execution-and-no-artifact-is-deployed"
GROUP = 'overly-permissive'
SERVICES = ['codepipeline']

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = 'codepipeline-missing-source'


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
    """A deterministic archive of the supplied entries, built in memory so the check owns the
    exact bytes it later demands back out of the artifact store."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry, body in entries.items():
            zf.writestr(entry, body)
    return buf.getvalue()


def _artifact_bucket(ctx) -> str:
    """A versioned artifact store, tagged so tag-based cleanup can find it if the run dies."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cp-")
    kw = {"Bucket": bucket}
    # us-east-1 is S3's implicit default location; CreateBucket rejects an explicit
    # LocationConstraint naming it, so the literal here is the region exception, not a pin.
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
    kw = {"pipeline": declaration}
    if tags:
        kw["tags"] = tags
    while True:
        try:
            return cp.create_pipeline(**kw)
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
    """Newest-first per the operation's contract, paginated across all pages."""
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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A missing S3 source object fails the execution with RevisionUnavailable, the Deploy stage
    never runs and nothing is deployed; uploading the object makes the same pipeline deliver it.
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    create_timeout_s = 180
    run_timeout_s = 300

    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    source_bytes = _zip({"payload.bin": os.urandom(1024)})
    source_sha = _sha(source_bytes)

    # Only the source object is absent; the control leg below reuses everything else unchanged.
    name = ctx.unique_name("sim2real-behav-cpmiss-")
    _create_with_role_propagation(
        cp,
        _pipeline(name, role_arn, bucket,
                  [_source_stage(bucket, "source.zip"),
                   {"name": "Deploy",
                    "actions": [_deploy_action("Deploy", bucket, "deployed/out.zip")]}]),
        timeout_s=create_timeout_s,
        tags=[{"key": "sim2real", "value": _SCENARIO}])
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    failing_id = _first_execution(cp, name, timeout_s=run_timeout_s)
    ctx.on_cleanup(lambda: _abandon(cp, name, failing_id))
    failed_status = _poll(lambda: _execution_status(cp, name, failing_id),
                          lambda s: s in _TERMINAL, timeout_s=run_timeout_s, interval_s=3)
    assert failed_status == "Failed", (
        f"a missing source object must fail the execution, and specifically Failed rather than "
        f"Stopped or Cancelled: execution {failing_id} reported {failed_status!r}, full record "
        f"{_execution(cp, name, failing_id)!r}"
    )

    source_latest = _poll(
        lambda: _action_state(cp, name, "Source", "Source").get("latestExecution", {}),
        lambda e: bool(e.get("errorDetails")), timeout_s=run_timeout_s, interval_s=3)
    error_details = source_latest.get("errorDetails", {})
    # AWS reports RevisionUnavailable here, not JobFailed.
    assert error_details.get("code") == "RevisionUnavailable", (
        f"the source failure must report errorDetails.code RevisionUnavailable, got "
        f"{error_details!r} (full action state {source_latest!r})"
    )

    # Real CodePipeline leaves latestExecution absent for an action that never ran.
    deploy_state = _action_state(cp, name, "Deploy", "Deploy")
    assert "latestExecution" not in deploy_state, (
        f"the Deploy action ran despite the Source action failing: {deploy_state!r}. An emulator "
        f"that advances every stage regardless of the previous one's outcome fails here."
    )
    assert _keys_under(s3, bucket, "deployed/") == [], (
        f"an artifact was delivered by a failed execution: "
        f"{_keys_under(s3, bucket, 'deployed/')!r}"
    )

    # The positive control, in this file: restore the one broken thing and nothing else.
    s3.put_object(Bucket=bucket, Key="source.zip", Body=source_bytes)
    control_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    ctx.on_cleanup(lambda: _abandon(cp, name, control_id))
    control_status = _poll(lambda: _execution_status(cp, name, control_id),
                           lambda s: s in _TERMINAL, timeout_s=run_timeout_s, interval_s=3)
    assert control_status == "Succeeded", (
        f"the control execution {control_id} must Succeed once the source object exists, "
        f"otherwise the failure above is not attributable to the missing object: "
        f"{control_status!r}, full record {_execution(cp, name, control_id)!r}"
    )
    _poll(lambda: _keys_under(s3, bucket, "deployed/"), lambda k: "deployed/out.zip" in k,
          timeout_s=run_timeout_s, interval_s=3)
    control_sha = _sha(s3.get_object(Bucket=bucket, Key="deployed/out.zip")["Body"].read())
    assert control_sha == source_sha, (
        f"the control execution did not deliver the source bytes ({control_sha!r} != "
        f"{source_sha!r}), so the effect-absent assertion above proves nothing"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
