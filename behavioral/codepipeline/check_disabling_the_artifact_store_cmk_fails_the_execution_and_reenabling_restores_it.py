"""disabling-the-artifact-store-cmk-fails-the-execution-and-reenabling-restores-it."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disabling-the-artifact-store-cmk-fails-the-execution-and-reenabling-restores-it"
GROUP = "artifact-integrity"
SERVICES = ["codepipeline"]

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = "codepipeline-artifact-store-cmk-disabled"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Disabling the artifactStore.encryptionKey CMK makes the next execution fail (JobFailed) with
    no artifact delivered; re-enabling it makes the identical execution succeed and redeliver the
    same bytes.
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    create_timeout_s = 240
    run_timeout_s = 300

    key = kms.create_key(
        Description=f"{_SCENARIO} {ctx.unique_name('k-')}",
        Tags=[{"TagKey": "sim2real", "TagValue": _SCENARIO}],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    bucket = _artifact_bucket(ctx, s3)
    source_bytes = _zip({"payload.bin": os.urandom(2048),
                         "note.txt": "sim2real codepipeline cmk withhold probe\n"})
    source_sha = _sha(source_bytes)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=source_bytes)
    role_arn = _pipeline_role(ctx, bucket, key_arn=key_arn)

    name = ctx.unique_name("sim2real-behav-cpkmsoff-")
    _create_with_role_propagation(
        ctx, cp, _pipeline(name, role_arn, bucket, key_arn),
        timeout_s=_budget_s(ctx, create_timeout_s))
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    # ---- beat 1: positive control, on this exact wiring, with the CMK enabled ----
    exec1 = _first_execution(ctx, cp, name, timeout_s=_budget_s(ctx, run_timeout_s))
    ctx.on_cleanup(lambda: _abandon(cp, name, exec1))
    started = time.monotonic()
    status1 = _await_terminal(ctx, cp, name, exec1, timeout_s=_budget_s(ctx, run_timeout_s))
    control_latency_s = time.monotonic() - started
    assert status1 == "Succeeded", (
        f"positive control: the first execution {exec1} of {name!r} must Succeed with the CMK "
        f"enabled, otherwise nothing below can distinguish 'the disabled key blocked it' from "
        f"'this pipeline never worked'; expected 'Succeeded', got {status1!r}. Record: "
        f"{_execution(cp, name, exec1)!r}"
    )
    delivered = _poll(ctx, lambda: _get_object(s3, bucket, "deployed/out.zip"),
                      lambda b: b is not None, timeout_s=_budget_s(ctx, run_timeout_s), interval_s=1,
                      what=f"the control execution to deploy deployed/out.zip into {bucket!r}")
    assert _sha(delivered) == source_sha, (
        f"positive control: the deployed artifact must be the source bytes; expected sha256 "
        f"{source_sha!r}, got {_sha(delivered)!r}"
    )

    # Remove the control's artifact so a later reappearance is unambiguous evidence of a NEW
    # delivery rather than a leftover.
    s3.delete_object(Bucket=bucket, Key="deployed/out.zip")
    _poll(ctx, lambda: _get_object(s3, bucket, "deployed/out.zip"), lambda b: b is None,
          timeout_s=_budget_s(ctx, 120), interval_s=1,
          what="the control artifact to be gone before the withhold leg begins")

    artifact_versions_before = _artifact_version_count(s3, bucket, name)

    # ---- beat 2: break exactly one thing ----
    kms.disable_key(KeyId=key_id)
    ctx.on_cleanup(lambda: _reenable(kms, key_id))
    _poll(ctx, lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["Enabled"],
          lambda enabled: enabled is False,
          timeout_s=_budget_s(ctx, 120), interval_s=1,
          what=f"CMK {key_id} to report Enabled=False after DisableKey (H3)")

    # ---- beat 3: the specific failure ----
    exec2 = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    ctx.on_cleanup(lambda: _abandon(cp, name, exec2))
    status2 = _await_terminal(ctx, cp, name, exec2, timeout_s=_budget_s(ctx, run_timeout_s))
    assert status2 == "Failed", (
        f"with the artifact store CMK disabled the execution must fail, not succeed: execution "
        f"{exec2} of {name!r} expected 'Failed', got {status2!r}. An emulator that treats "
        f"artifactStore.encryptionKey as an inert string reports 'Succeeded' here. Record: "
        f"{_execution(cp, name, exec2)!r}"
    )
    failed_action = _failed_action_state(cp, name, exec2)
    details = failed_action.get("latestExecution", {}).get("errorDetails") or {}
    assert details, (
        f"the failing action must report errorDetails naming why the artifact hand-off failed, "
        f"not fail silently; action state was {failed_action!r}"
    )
    # errorDetails does not mention KMS for a disabled artifact-store CMK; it is the generic
    # internal-error shape. Attribution rests on the same call succeeding before and after.
    assert details.get("code") == "JobFailed", (
        f"with the artifact store CMK disabled the Source action must fail with errorDetails.code "
        f"'JobFailed'; expected 'JobFailed', got {details.get('code')!r}. Full errorDetails: "
        f"{details!r}"
    )
    assert re.match(r"^InternalError\. Error reference code: [0-9a-f-]+\.$",
                    details.get("message", "")), (
        f"the failing action's errorDetails.message must be CodePipeline's generic internal-error "
        f"shape 'InternalError. Error reference code: <uuid>.'; got {details.get('message')!r}"
    )

    # ---- beat 4: effect absent, by an independent read at the destination ----
    # No timing window is needed: exec2 is already terminal, so nothing can still deliver.
    assert _get_object(s3, bucket, "deployed/out.zip") is None, (
        f"execution {exec2} Failed, so no artifact may have been deployed to "
        f"deployed/out.zip in {bucket!r}; an object is present"
    )
    after = _artifact_version_count(s3, bucket, name)
    assert after == artifact_versions_before, (
        f"a failed execution must not add an artifact version under {name}/ in {bucket!r}: "
        f"expected {artifact_versions_before} as before the CMK was disabled, got {after}"
    )

    # ---- beat 5: restore ----
    kms.enable_key(KeyId=key_id)
    _poll(ctx, lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["Enabled"],
          lambda enabled: enabled is True,
          timeout_s=_budget_s(ctx, 120), interval_s=1,
          what=f"CMK {key_id} to report Enabled=True after EnableKey")

    # ---- beat 6: the identical call now succeeds and redelivers the same bytes ----
    exec3 = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    ctx.on_cleanup(lambda: _abandon(cp, name, exec3))
    status3 = _await_terminal(ctx, cp, name, exec3, timeout_s=_budget_s(ctx, run_timeout_s))
    assert status3 == "Succeeded", (
        f"after re-enabling the CMK the identical StartPipelineExecution must succeed; execution "
        f"{exec3} of {name!r} expected 'Succeeded', got {status3!r}. A target that fakes the "
        f"withhold by simply never delivering fails this restore leg. Record: "
        f"{_execution(cp, name, exec3)!r}"
    )
    redelivered = _poll(
        ctx, lambda: _get_object(s3, bucket, "deployed/out.zip"), lambda b: b is not None,
        timeout_s=_budget_s(ctx, run_timeout_s), interval_s=1,
        what=f"the restored execution to redeliver deployed/out.zip (control took "
             f"{control_latency_s:.0f}s)")
    assert _sha(redelivered) == source_sha, (
        f"the redelivered artifact must be the same bytes the control delivered: expected sha256 "
        f"{source_sha!r}, got {_sha(redelivered)!r}"
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
    """The object bytes, or None if it is absent."""
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404", "NotFound"):
            return None
        raise


def _reenable(kms, key_id) -> None:
    """Never leave this check's CMK disabled."""
    try:
        kms.enable_key(KeyId=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
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
    bucket = ctx.unique_name("sim2real-behav-cpkmsoff-").lower()
    kw = {"Bucket": bucket}
    # CreateBucket rejects LocationConstraint="us-east-1".
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _artifact_version_count(s3, bucket, pipeline_name) -> int:
    """How many object versions exist under the pipeline's own artifact prefix."""
    n = 0
    for page in s3.get_paginator("list_object_versions").paginate(
            Bucket=bucket, Prefix=f"{pipeline_name}/"):
        n += len(page.get("Versions", []))
    return n


def _pipeline_role(ctx, bucket, *, key_arn) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cpkmsoff-")
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
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                               "s3:GetBucketVersioning", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                },
                {
                    # Scoped to this run's CMK so the role cannot reach any other key.
                    "Effect": "Allow",
                    "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom",
                               "kms:ReEncryptTo", "kms:GenerateDataKey",
                               "kms:GenerateDataKeyWithoutPlaintext", "kms:DescribeKey"],
                    "Resource": key_arn,
                },
            ],
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


def _pipeline(name, role_arn, bucket, key_arn):
    """Source(S3) -> Deploy(S3) only, so an execution cannot start a build or a stack."""
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket,
                          "encryptionKey": {"id": key_arn, "type": "KMS"}},
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
                                  "ObjectKey": "deployed/out.zip"},
                "inputArtifacts": [{"name": "SourceOutput"}],
            }]},
        ],
    }


def _execution(cp, name, execution_id):
    return cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]


def _execution_status(cp, name, execution_id):
    try:
        return _execution(cp, name, execution_id)["status"]
    except ClientError:
        return None


def _await_terminal(ctx, cp, name, execution_id, *, timeout_s):
    """Poll to any terminal status; callers assert which one was reached."""
    return _poll(ctx, lambda: _execution_status(cp, name, execution_id),
                 lambda s: s in _TERMINAL, timeout_s=timeout_s, interval_s=1,
                 what=f"execution {execution_id} of {name!r} to reach a terminal status")


def _failed_action_state(cp, name, execution_id):
    """The state of the action that failed in this execution.

    Only stageStates[].latestExecution carries pipelineExecutionId, not the action's."""
    state = cp.get_pipeline_state(name=name)
    for stage in state.get("stageStates", []):
        if stage.get("latestExecution", {}).get("pipelineExecutionId") != execution_id:
            continue
        for action in stage.get("actionStates", []):
            if action.get("latestExecution", {}).get("status") == "Failed":
                return action
    raise AssertionError(
        f"expected exactly one action of execution {execution_id} to report status Failed after "
        f"the artifact-store CMK was disabled; no such action in GetPipelineState: {state!r}"
    )


def _execution_ids(cp, name):
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _first_execution(ctx, cp, name, *, timeout_s):
    ids = _poll(ctx, lambda: _execution_ids(cp, name), lambda i: len(i) >= 1,
                timeout_s=timeout_s, interval_s=1,
                what=f"CreatePipeline to auto-start an execution of {name!r}")
    return ids[0]


def _abandon(cp, name, execution_id):
    try:
        cp.stop_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real behavioral check teardown")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "PipelineNotFoundException":
            return
        if code != "PipelineExecutionNotStoppableException":
            raise
        # Not stoppable is the outcome teardown wants only when the execution has already ended.
        status = cp.get_pipeline_execution(
            pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]["status"]
        if status not in ("Succeeded", "Failed", "Stopped", "Stopping", "Superseded", "Cancelled"):
            raise RuntimeError(f"execution {execution_id} of {name} was not stopped: {status}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
