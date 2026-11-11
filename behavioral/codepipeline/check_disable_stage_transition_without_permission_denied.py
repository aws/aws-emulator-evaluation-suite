"""disable-stage-transition-without-permission-denied."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-stage-transition-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]
_SCENARIO = "disable-stage-transition-without-permission-denied"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A caller whose IAM policy explicitly denies codepipeline:DisableStageTransition is
    rejected with AccessDeniedException rather than the transition silently flipping, and the
    same call from a fully-permitted caller (positive control) actually disables it."""
    cp = ctx.client("codepipeline")
    sts = ctx.client("sts")
    bucket, key = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = _create_pipeline(
        ctx, [_source_stage(bucket, key), _approval_stage("Approval", "Approve")], role_arn, bucket
    )

    account_id = sts.get_caller_identity()["Account"]
    restricted_role_arn = _create_restricted_role(ctx, account_id)
    session_name = ctx.unique_name(_PREFIX + "sess-")[:64]
    restricted_cp = _assume_role_client(ctx, restricted_role_arn, "codepipeline", session_name)

    code, message = _error(
        lambda: restricted_cp.disable_stage_transition(
            pipelineName=name, stageName="Approval", transitionType="Inbound", reason="attempted-without-permission"
        )
    )
    assert code == "AccessDeniedException", (
        f"expected the explicit Deny on codepipeline:DisableStageTransition to surface as "
        f"AccessDeniedException; got {code!r}"
    )
    restricted_role_name = restricted_role_arn.rsplit("/", 1)[-1]
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{restricted_role_name}/{session_name} "
        "is not authorized to perform: codepipeline:DisableStageTransition on resource: "
        f"arn:aws:codepipeline:{ctx.region}:{account_id}:{name}/Approval "
        "with an explicit deny in an identity-based policy"
    ), f"unexpected AccessDeniedException message: {message!r}"

    # Effect absent: inbound transition on Approval is still enabled.
    enabled_before = _inbound_enabled(ctx, name, "Approval")
    assert enabled_before is True, (
        f"the denied call must have no effect: expected the Approval stage's inbound transition "
        f"to remain enabled; GetPipelineState reported enabled={enabled_before!r}"
    )

    # Positive control: the fully-permitted caller can actually disable it.
    cp.disable_stage_transition(
        pipelineName=name, stageName="Approval", transitionType="Inbound", reason="admin-disable"
    )
    enabled_after = _inbound_enabled(ctx, name, "Approval")
    assert enabled_after is False, (
        f"the identical call from a fully-permitted caller must actually disable the transition: "
        f"expected enabled=False, GetPipelineState reported enabled={enabled_after!r}"
    )


_PREFIX = "sim2real-cpbeh-"


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS denies is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


def _safe_bucket_name(ctx, base: str) -> str:
    raw = ctx.unique_name(base).lower()
    raw = re.sub(r"[^a-z0-9.-]", "-", raw)
    return raw[:63]


def _make_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("buildspec.yml", "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n")
    return buf.getvalue()


def _create_artifact_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = _safe_bucket_name(ctx, _PREFIX + "art-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    key = "source.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_make_zip_bytes())
    return bucket, key


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
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
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(_PREFIX + "role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetBucketVersioning", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="cp-inline", PolicyDocument=json.dumps(policy_doc))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="cp-inline")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_restricted_role(ctx, account_id: str) -> str:
    """A role assumable by this same account, but with an explicit Deny on
    codepipeline:DisableStageTransition (and Allow on read-only calls) -- an explicit Deny
    always wins over any broader Allow, so this cannot accidentally be permissive."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(_PREFIX + "restricted-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["codepipeline:GetPipelineState", "codepipeline:GetPipeline"], "Resource": "*"},
            {"Effect": "Deny", "Action": "codepipeline:DisableStageTransition", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="restricted-inline", PolicyDocument=json.dumps(policy_doc))
    return role["Arn"]


def _assume_role_client(ctx, role_arn: str, service: str, session_name: str, timeout_s: float = 60.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as e:
            last_exc = e
            time.sleep(3)
    raise AssertionError(f"assume_role never succeeded: {last_exc}")


def _source_stage(bucket: str, key: str) -> dict[str, Any]:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
                "runOrder": 1,
            }
        ],
    }


def _approval_stage(stage_name: str, action_name: str) -> dict[str, Any]:
    return {
        "name": stage_name,
        "actions": [
            {
                "name": action_name,
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                "configuration": {},
                "runOrder": 1,
            }
        ],
    }


def _create_pipeline(ctx, stages: list[dict[str, Any]], role_arn: str, bucket: str, timeout_s: float = 90.0) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name(_PREFIX + "pipe-")
    pipeline_dict = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = cp.create_pipeline(
                pipeline=pipeline_dict, tags=[{"key": "sim2real", "value": _SCENARIO}]
            )
            ctx.on_cleanup(lambda n=name: cp.delete_pipeline(name=n))
            return resp["pipeline"]["name"]
        except ClientError as e:
            last_exc = e
            time.sleep(3)
    raise AssertionError(f"create_pipeline never succeeded: {last_exc}")


def _inbound_enabled(ctx, pipeline_name: str, stage_name: str) -> bool | None:
    cp = ctx.client("codepipeline")
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state["stageStates"]:
        if stage["stageName"] == stage_name:
            return stage.get("inboundTransitionState", {}).get("enabled")
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
