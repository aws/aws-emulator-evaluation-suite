"""disable-stage-transition-nonexistent-stage-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-stage-transition-nonexistent-stage-rejected"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableStageTransition targeting a stage name absent from the pipeline is rejected with
    StageNotFoundException rather than being accepted and ignored; it leaves the real stage's
    transition state untouched, and disabling the real stage name still works normally."""
    cp = ctx.client("codepipeline")
    role_arn = _cp_create_role(ctx)
    bucket = _cp_create_bucket(ctx)
    provider = _cp_create_custom_source_type(ctx)
    pipeline = _cp_create_pipeline(ctx, role_arn, bucket, provider)

    before = _stage_inbound_enabled(ctx, pipeline, "Source")
    assert before is True, f"expected Source inbound enabled before any call, got {before}"

    code, message = _error(
        lambda: cp.disable_stage_transition(
            pipelineName=pipeline, stageName="NoSuchStage-zzz", transitionType="Inbound", reason="probe"
        )
    )
    assert code == "StageNotFoundException", f"expected StageNotFoundException, got {code}"
    assert message == f"Pipeline '{pipeline}' does not have a stage with name 'NoSuchStage-zzz'", f"unexpected message: {message!r}"

    # effect absent: the real stage's transition state was not touched by the rejected call
    still = _stage_inbound_enabled(ctx, pipeline, "Source")
    assert still is True, f"expected Source inbound still enabled after rejected call, got {still}"

    # positive control: disabling the real stage name works normally
    cp.disable_stage_transition(
        pipelineName=pipeline, stageName="Source", transitionType="Inbound", reason="disable for real"
    )
    after = _poll_until_inbound(ctx, pipeline, "Source", expected=False)
    assert after is False, f"expected Source inbound disabled after the real call, got {after}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _cp_create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "disable-stage-transition-nonexistent-stage-rejected"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="cp-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="cp-access"))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    return role_arn


def _cp_create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    # LocationConstraint is rejected for us-east-1 specifically; every other region requires it.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "disable-stage-transition-nonexistent-stage-rejected"}]},
    )
    return bucket


def _cp_create_custom_source_type(ctx) -> str:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("cpsrc-")[:25]
    cp.create_custom_action_type(
        category="Source",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        tags=[{"key": "sim2real", "value": "disable-stage-transition-nonexistent-stage-rejected"}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Source", provider=provider, version="1"))
    return provider


def _cp_create_pipeline(ctx, role_arn, bucket, provider, extra_stages=None) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pipe-")
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "Custom", "provider": provider, "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        }
    ]
    if extra_stages:
        stages.extend(extra_stages)
    else:
        # CodePipeline requires a minimum of 2 stages.
        stages.append(
            {
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
        )
    deadline = time.monotonic() + 30
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(
                pipeline={
                    "name": name,
                    "roleArn": role_arn,
                    "artifactStore": {"type": "S3", "location": bucket},
                    "stages": stages,
                },
                tags=[{"key": "sim2real", "value": "disable-stage-transition-nonexistent-stage-rejected"}],
            )
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise last_exc
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _stage_inbound_enabled(ctx, pipeline_name, stage_name) -> bool:
    cp = ctx.client("codepipeline")
    state = cp.get_pipeline_state(name=pipeline_name)
    for s in state["stageStates"]:
        if s["stageName"] == stage_name:
            return s["inboundTransitionState"]["enabled"]
    raise AssertionError(f"stage {stage_name} not found in pipeline state")


def _poll_until_inbound(ctx, pipeline_name, stage_name, expected, timeout_s=60) -> bool:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _stage_inbound_enabled(ctx, pipeline_name, stage_name)
        if last == expected:
            return last
        time.sleep(2)
    raise AssertionError(f"stage {stage_name} inbound enabled never reached {expected}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
