"""disable-stage-transition-unknown-stage-not-permissive."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "disable-stage-transition-unknown-stage-not-permissive"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableStageTransition on an unknown stage fails with StageNotFoundException and its exact message,
    leaving both real transitions enabled, while disabling the real Approve stage's inbound transition
    succeeds.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx)
    name = ctx.unique_name("sim2real-cp-unkstage-")
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
            "name": "Approve",
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

    before = cp.get_pipeline_state(name=name)
    before_enabled = {
        s["stageName"]: s.get("inboundTransitionState", {}).get("enabled", True)
        for s in before["stageStates"]
    }
    assert before_enabled == {"Source": True, "Approve": True}

    code, message = _error(
        lambda: cp.disable_stage_transition(
            pipelineName=name,
            stageName="NoSuchStage-does-not-exist",
            transitionType="Inbound",
            reason="behavioral fidelity check",
        )
    )
    assert code == "StageNotFoundException", f"unexpected code: {code}"
    assert message == f"Pipeline '{name}' does not have a stage with name 'NoSuchStage-does-not-exist'", f"unexpected message: {message!r}"

    # effect absent: no real stage's transition state changed.
    after_bad = cp.get_pipeline_state(name=name)
    after_bad_enabled = {
        s["stageName"]: s.get("inboundTransitionState", {}).get("enabled", True)
        for s in after_bad["stageStates"]
    }
    assert after_bad_enabled == {"Source": True, "Approve": True}

    # positive control: disabling a real stage's transition does take effect.
    cp.disable_stage_transition(
        pipelineName=name,
        stageName="Approve",
        transitionType="Inbound",
        reason="behavioral fidelity check",
    )
    after_good = cp.get_pipeline_state(name=name)
    approve_state = next(s for s in after_good["stageStates"] if s["stageName"] == "Approve")
    assert approve_state["inboundTransitionState"]["enabled"] is False


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-unkstage-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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


def _create_role(ctx):
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
    # IAM roles can take a short time to propagate before another service can
    # assume them: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    # Full propagation isn't independently observable here; _create_pipeline's own
    # bounded retry on InvalidStructureException is what actually absorbs the remaining lag.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if iam.get_role(RoleName=role_name)["Role"]["RoleName"] == role_name:
            break
        time.sleep(1)
    return role["Arn"]


def _create_pipeline(ctx, name, role_arn, bucket, stages):
    from botocore.exceptions import ClientError

    cp = ctx.client("codepipeline")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    deadline = time.monotonic() + 60
    while True:
        try:
            result = cp.create_pipeline(
                pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}]
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidStructureException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
