"""stage-transition-disable-enable-toggles-state."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stage-transition-disable-enable-toggles-state"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableStageTransition marks the stage's inbound transition disabled in
    GetPipelineState (with the given reason); EnableStageTransition reverses it."""
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")

    source_bucket = _create_bucket(ctx, "toggle-src")
    artifact_bucket = _create_bucket(ctx, "toggle-art")
    s3.put_object(Bucket=source_bucket, Key="app.zip", Body=_make_zip_bytes())
    role_arn = _create_pipeline_role(ctx, [source_bucket, artifact_bucket])

    name = ctx.unique_name("sim2real-cp-toggle-")
    pipeline_def = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [_source_stage(source_bucket, "app.zip"), _approval_stage()],
    }
    _create_pipeline_with_retry(ctx, cp, pipeline_def)
    _register_pipeline_cleanup(ctx, cp, name)

    reason = "sim2real-disable-for-test"
    cp.disable_stage_transition(
        pipelineName=name,
        stageName="Approval",
        transitionType="Inbound",
        reason=reason,
    )

    def _approval_stage_state():
        state = cp.get_pipeline_state(name=name)
        return next(s for s in state["stageStates"] if s["stageName"] == "Approval")

    disabled_stage = _poll_until(
        _approval_stage_state,
        lambda s: s["inboundTransitionState"]["enabled"] is False,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert disabled_stage["inboundTransitionState"]["disabledReason"] == reason

    cp.enable_stage_transition(
        pipelineName=name, stageName="Approval", transitionType="Inbound"
    )
    enabled_stage = _poll_until(
        _approval_stage_state,
        lambda s: s["inboundTransitionState"]["enabled"] is True,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert enabled_stage["inboundTransitionState"]["enabled"] is True


# ===== helpers =====

def _make_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.txt", "hello-codepipeline")
    return buf.getvalue()


def _create_bucket(ctx, suffix: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-cp-{suffix}-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            versions = s3.list_object_versions(Bucket=name)
            to_delete = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
            ]
            if to_delete:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": to_delete}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _create_pipeline_role(ctx, bucket_names: list) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    resources = []
    for b in bucket_names:
        resources.append(f"arn:aws:s3:::{b}")
        resources.append(f"arn:aws:s3:::{b}/*")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": resources}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _source_stage(bucket: str, key: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "SourceAction",
                "actionTypeId": {
                    "category": "Source",
                    "owner": "AWS",
                    "provider": "S3",
                    "version": "1",
                },
                "outputArtifacts": [{"name": "SourceArtifact"}],
                "configuration": {
                    "S3Bucket": bucket,
                    "S3ObjectKey": key,
                    "PollForSourceChanges": "false",
                },
            }
        ],
    }


def _approval_stage() -> dict:
    return {
        "name": "Approval",
        "actions": [
            {
                "name": "ApprovalAction",
                "actionTypeId": {
                    "category": "Approval",
                    "owner": "AWS",
                    "provider": "Manual",
                    "version": "1",
                },
            }
        ],
    }


def _create_pipeline_with_retry(
    ctx, cp, pipeline_def: dict, timeout_s: float = 90.0, interval_s: float = 5.0
) -> None:
    """The role CodePipeline is handed may not be assumable yet (IAM trust-policy
    propagation lag); retry the structural failure it produces instead of a fixed sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cp.create_pipeline(
                pipeline=pipeline_def, tags=[{"key": "sim2real", "value": CHECK}]
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "InvalidStructureException" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _register_pipeline_cleanup(ctx, cp, name: str) -> None:
    def _cleanup():
        try:
            cp.delete_pipeline(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PipelineNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
