"""server-enforces-disabled-stage-transition-blocks-progress."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-enforces-disabled-stage-transition-blocks-progress"
GROUP = "server-side"
SERVICES = ["codepipeline"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After DisableStageTransition, a started execution halts before the stage and its action
    never starts; EnableStageTransition resumes it, so the gate is enforced server-side."""
    cp = ctx.client("codepipeline")
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, bucket)
    _upload_source_zip(ctx, bucket, "source.zip")

    name = ctx.unique_name("sim2real-cp-gate-")
    stages = [
        {
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
                    "configuration": {
                        "S3Bucket": bucket,
                        "S3ObjectKey": "source.zip",
                        "PollForSourceChanges": "false",
                    },
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        },
        {
            "name": "Gate",
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
        },
    ]
    _create_pipeline(ctx, name, role_arn, bucket, stages)

    cp.disable_stage_transition(
        pipelineName=name,
        stageName="Gate",
        transitionType="Inbound",
        reason="behavioral fidelity gate check",
    )

    cp.start_pipeline_execution(name=name)

    _wait_for_stage_status(ctx, name, "Source", "Succeeded", timeout_s=120)

    # Give the (disabled) downstream stage a generous grace window: if the server
    # enforced the gate only client-side / cosmetically, the approval action would
    # start (get a latestExecution) despite the transition being disabled.
    deadline = time.monotonic() + 20
    gate_started = False
    while time.monotonic() < deadline:
        state = cp.get_pipeline_state(name=name)
        gate = next(s for s in state["stageStates"] if s["stageName"] == "Gate")
        assert gate["inboundTransitionState"]["enabled"] is False
        if gate.get("actionStates") and gate["actionStates"][0].get("latestExecution"):
            gate_started = True
            break
        time.sleep(2)
    assert not gate_started, "Gate stage action started despite disabled inbound transition"

    cp.enable_stage_transition(pipelineName=name, stageName="Gate", transitionType="Inbound")

    _wait_for_action_started(ctx, name, "Gate", "ApprovalAction", timeout_s=60)

    resumed_state = cp.get_pipeline_state(name=name)
    gate_after = next(s for s in resumed_state["stageStates"] if s["stageName"] == "Gate")
    assert gate_after["inboundTransitionState"]["enabled"] is True
    assert gate_after["actionStates"][0]["latestExecution"]["status"] == "InProgress"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-gate-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # us-east-1 is the one region that rejects a LocationConstraint on CreateBucket.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        objs = s3.list_object_versions(Bucket=bucket)
        to_delete = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in objs.get("Versions", []) + objs.get("DeleteMarkers", [])
        ]
        if to_delete:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": to_delete}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_source_zip(ctx, bucket, key):
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral check artifact")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _create_role(ctx, bucket):
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-s3"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if iam.get_role(RoleName=role_name)["Role"]["RoleName"] == role_name:
            break
        time.sleep(1)
    return role["Arn"]


def _create_pipeline(ctx, name, role_arn, bucket, stages, *, timeout_s=90.0):
    # IAM roles/policies can take a short time to propagate before CodePipeline can assume
    # them: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    # Retry create_pipeline itself against that real signal rather than sleeping blind.
    cp = ctx.client("codepipeline")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            result = cp.create_pipeline(
                pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}]
            )
            ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
            return result
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code not in ("InvalidStructureException", "InvalidParameterValueException", "InvalidRoleException"):
                raise
            last_exc = e
            time.sleep(3)
    raise AssertionError(f"create_pipeline never succeeded (role propagation?): {last_exc}")


def _wait_for_stage_status(ctx, pipeline_name, stage_name, expected_status, *, timeout_s=120.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        state = cp.get_pipeline_state(name=pipeline_name)
        stage = next(s for s in state["stageStates"] if s["stageName"] == stage_name)
        last = stage.get("latestExecution", {}).get("status")
        if last == expected_status:
            return
        time.sleep(interval_s)
    raise AssertionError(f"stage {stage_name} never reached {expected_status}, last saw {last}")


def _wait_for_action_started(ctx, pipeline_name, stage_name, action_name, *, timeout_s=60.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = cp.get_pipeline_state(name=pipeline_name)
        stage = next(s for s in state["stageStates"] if s["stageName"] == stage_name)
        action = next(
            (a for a in stage.get("actionStates", []) if a["actionName"] == action_name), None
        )
        if action and action.get("latestExecution"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"action {action_name} in stage {stage_name} never started within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
