"""artifact-store-cmk-encrypts-the-delivered-artifact-object."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "artifact-store-cmk-encrypts-the-delivered-artifact-object"
GROUP = "artifact-integrity"
SERVICES = ["codepipeline"]

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = "codepipeline-artifact-store-cmk"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The artifact CodePipeline writes is SSE-KMS encrypted under the declared encryptionKey CMK.
    An otherwise identical pipeline without encryptionKey does not use that CMK.

    Reference: https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_EncryptionKey.html
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

    source_bytes = _zip({"payload.bin": _random_bytes(2048)})

    # Two independent artifact stores so the encrypted and the control artifact can never be
    # confused for one another, and so listing a pipeline's prefix cannot pick up the twin's.
    enc_bucket = _artifact_bucket(ctx, s3)
    ctl_bucket = _artifact_bucket(ctx, s3)
    s3.put_object(Bucket=enc_bucket, Key="source.zip", Body=source_bytes)
    s3.put_object(Bucket=ctl_bucket, Key="source.zip", Body=source_bytes)

    enc_role = _pipeline_role(ctx, enc_bucket, key_arn=key_arn)
    ctl_role = _pipeline_role(ctx, ctl_bucket, key_arn=None)

    enc_name = ctx.unique_name("sim2real-behav-cpkms-")
    ctl_name = ctx.unique_name("sim2real-behav-cpctl-")

    # Both pipelines are created before either is awaited: CreatePipeline auto-starts an
    # execution, so the two executions overlap and the wall clock is one execution, not two.
    _create_with_role_propagation(
        cp,
        _pipeline(enc_name, enc_role, enc_bucket,
                  encryption_key={"id": key_arn, "type": "KMS"}),
        timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=enc_name))
    _create_with_role_propagation(
        cp, _pipeline(ctl_name, ctl_role, ctl_bucket, encryption_key=None),
        timeout_s=create_timeout_s)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=ctl_name))

    enc_exec = _first_execution(cp, enc_name, timeout_s=run_timeout_s)
    ctl_exec = _first_execution(cp, ctl_name, timeout_s=run_timeout_s)
    ctx.on_cleanup(lambda: _abandon(cp, enc_name, enc_exec))
    ctx.on_cleanup(lambda: _abandon(cp, ctl_name, ctl_exec))

    for name, exec_id in ((enc_name, enc_exec), (ctl_name, ctl_exec)):
        status = _poll(lambda: _execution_status(cp, name, exec_id),
                       lambda s: s in _TERMINAL,
                       timeout_s=run_timeout_s, interval_s=5,
                       what=f"execution {exec_id} of {name!r} to reach a terminal status")
        assert status == "Succeeded", (
            f"pipeline {name!r} execution {exec_id} must reach Succeeded so an artifact is "
            f"actually written to its store; expected 'Succeeded', got {status!r}. Full "
            f"record: {_execution(cp, name, exec_id)!r}"
        )

    # The artifact CodePipeline itself wrote, not the object this check uploaded.
    enc_key_name = _artifact_object_key(s3, enc_bucket, enc_name, timeout_s=run_timeout_s)
    ctl_key_name = _artifact_object_key(s3, ctl_bucket, ctl_name, timeout_s=run_timeout_s)

    enc_head = s3.head_object(Bucket=enc_bucket, Key=enc_key_name)
    assert enc_head.get("ServerSideEncryption") == "aws:kms", (
        f"the artifact object {enc_key_name!r} written by pipeline {enc_name!r} (which declares "
        f"artifactStore.encryptionKey type KMS) must be SSE-KMS encrypted; expected "
        f"ServerSideEncryption 'aws:kms', got {enc_head.get('ServerSideEncryption')!r}"
    )
    enc_used = enc_head.get("SSEKMSKeyId") or ""
    assert key_id in enc_used, (
        f"the artifact object must be encrypted under the CMK named in "
        f"artifactStore.encryptionKey, not a default key: expected a key id containing "
        f"{key_id!r} (declared {key_arn!r}), got SSEKMSKeyId {enc_used!r}. An emulator that "
        f"stores and echoes encryptionKey but writes the artifact with bucket-default "
        f"encryption fails exactly here."
    )

    # Control: the same pipeline shape with NO encryptionKey must not have used this CMK.
    # Without this leg, "every object is encrypted with the only key in the account" would pass.
    ctl_head = s3.head_object(Bucket=ctl_bucket, Key=ctl_key_name)
    ctl_used = ctl_head.get("SSEKMSKeyId") or ""
    assert key_id not in ctl_used, (
        f"control pipeline {ctl_name!r} declares NO artifactStore.encryptionKey, so its artifact "
        f"object {ctl_key_name!r} must not be encrypted under this check's CMK; expected "
        f"SSEKMSKeyId without {key_id!r}, got {ctl_used!r} (ServerSideEncryption "
        f"{ctl_head.get('ServerSideEncryption')!r}). If this fires, the encrypted leg above "
        f"proves nothing about the field being honoured."
    )

    # The declared field must still round-trip, so a target cannot pass the encryption leg by
    # silently substituting a different key into its own declaration.
    declared = cp.get_pipeline(name=enc_name)["pipeline"]["artifactStore"].get("encryptionKey")
    assert declared == {"id": key_arn, "type": "KMS"}, (
        f"GetPipeline must return the encryptionKey as declared with no substitution; expected "
        f"{{'id': {key_arn!r}, 'type': 'KMS'}}, got {declared!r}"
    )


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """A bounded retry that raises on timeout, so a truncated wait never counts as satisfied."""
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


def _random_bytes(n: int) -> bytes:
    """os.urandom, so a delivered artifact can only match by having actually been copied."""
    import os

    return os.urandom(n)


def _zip(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry, body in entries.items():
            zf.writestr(entry, body)
    return buf.getvalue()


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _purge_bucket(s3, bucket) -> None:
    """Each execution writes a new artifact version; a versioned bucket needs version-aware
    deletion or DeleteBucket fails."""
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
    """A versioned artifact store, tagged so tag-based cleanup can discover it."""
    bucket = ctx.unique_name("sim2real-behav-cpkms-").lower()
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's implicit default; passing a LocationConstraint of
        # "us-east-1" is itself rejected, so the literal names that one region, not a pin.
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _pipeline_role(ctx, bucket, *, key_arn) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cpkms-")
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
    statements = [{
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                   "s3:GetBucketVersioning", "s3:ListBucket"],
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
    }]
    if key_arn is not None:
        # Scoped to this run's CMK, so the role cannot reach any other key in the account.
        statements.append({
            "Effect": "Allow",
            "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo",
                       "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext",
                       "kms:DescribeKey"],
            "Resource": key_arn,
        })
    iam.put_role_policy(
        RoleName=name, PolicyName="artifacts",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"))
    return f"arn:aws:iam::{_account_id(ctx)}:role/{name}"


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    """CreatePipeline validates that it can assume the role, so it answers
    InvalidStructureException while the freshly created role is still propagating. IAM exposes no
    condition to poll for that, so the bounded retry IS the wait -- no bare sleep stands in."""
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


def _source_stage(bucket, key):
    return {"name": "Source", "actions": [{
        "name": "Source",
        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
        "runOrder": 1,
        "configuration": {"S3Bucket": bucket, "S3ObjectKey": key,
                          "PollForSourceChanges": "false"},
        "outputArtifacts": [{"name": "SourceOutput"}],
    }]}


def _deploy_action(action_name, bucket, object_key):
    return {
        "name": action_name,
        "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "S3", "version": "1"},
        "runOrder": 1,
        "configuration": {"BucketName": bucket, "Extract": "false", "ObjectKey": object_key},
        "inputArtifacts": [{"name": "SourceOutput"}],
    }


def _pipeline(name, role_arn, bucket, *, encryption_key):
    """Source(S3) -> Deploy(S3) only: a small object fetch and a small object write inside the
    same bucket, so an execution here cannot start a build, a deployment or a stack."""
    store = {"type": "S3", "location": bucket}
    if encryption_key is not None:
        store["encryptionKey"] = encryption_key
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": store,
        "pipelineType": "V2",
        "executionMode": "QUEUED",
        "stages": [_source_stage(bucket, "source.zip"),
                   {"name": "Deploy",
                    "actions": [_deploy_action("Deploy", bucket, "deployed/out.zip")]}],
    }


def _execution(cp, name, execution_id):
    return cp.get_pipeline_execution(
        pipelineName=name, pipelineExecutionId=execution_id)["pipelineExecution"]


def _execution_status(cp, name, execution_id):
    try:
        return _execution(cp, name, execution_id)["status"]
    except ClientError:
        return None


def _execution_ids(cp, name):
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _first_execution(cp, name, *, timeout_s):
    """CreatePipeline starts an execution of its own; that is the execution this check grades, so
    there is no StartPipelineExecution racing it."""
    ids = _poll(lambda: _execution_ids(cp, name), lambda i: len(i) >= 1,
                timeout_s=timeout_s, interval_s=3,
                what=f"CreatePipeline to auto-start an execution of {name!r}")
    return ids[0]


_SELF_WRITTEN_KEYS = frozenset({"source.zip", "deployed/out.zip"})


def _artifact_object_key(s3, bucket, pipeline_name, *, timeout_s) -> str:
    """The object CodePipeline itself wrote for the SourceOutput artifact.

    AWS does not prefix it with the pipeline name, so this lists the whole bucket and subtracts
    the two keys the check wrote itself; it fails if no artifact object appears.
    """
    def _listing():
        keys = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys.extend(o["Key"] for o in page.get("Contents", []))
        return sorted(k for k in keys if k not in _SELF_WRITTEN_KEYS)

    keys = _poll(_listing, lambda k: len(k) >= 1, timeout_s=timeout_s, interval_s=5,
                 what=f"an artifact object written by CodePipeline (i.e. not "
                      f"{sorted(_SELF_WRITTEN_KEYS)!r}) to appear in {bucket!r}")
    assert len(keys) == 1, (
        f"expected exactly one artifact object in {bucket!r} beyond this check's own "
        f"{sorted(_SELF_WRITTEN_KEYS)!r} for a single-artifact pipeline, found {len(keys)}: "
        f"{keys!r}"
    )
    return keys[0]


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
