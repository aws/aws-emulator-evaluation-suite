"""stage-transition-disable-enable-reflected-in-state."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stage-transition-disable-enable-reflected-in-state"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableStageTransition then EnableStageTransition toggles the inbound transition
    state of a stage as reported by GetPipelineState, including the disabledReason text."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_action = _create_custom_action_type(ctx, "Source", ctx.unique_name("SimSrc").replace("-", ""), output_range=(1, 1))
    build_action = _create_custom_action_type(ctx, "Build", ctx.unique_name("SimBld").replace("-", ""), input_range=(1, 1))

    name = ctx.unique_name("sim2real-cp-")
    pipeline_def = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": _worker_pipeline_stages(source_action["provider"], build_action["provider"]),
    }
    _create_pipeline(ctx, pipeline_def)

    reason = "Waiting for manual tests"
    cp.disable_stage_transition(pipelineName=name, stageName="Build", transitionType="Inbound", reason=reason)

    state = cp.get_pipeline_state(name=name)
    build_state = next(s for s in state["stageStates"] if s["stageName"] == "Build")
    inbound = build_state["inboundTransitionState"]
    assert inbound["enabled"] is False, f"expected inbound transition disabled after DisableStageTransition, got enabled={inbound['enabled']!r}"
    assert inbound["disabledReason"] == reason, f"expected disabledReason={reason!r}, got {inbound.get('disabledReason')!r}"

    cp.enable_stage_transition(pipelineName=name, stageName="Build", transitionType="Inbound")

    state2 = cp.get_pipeline_state(name=name)
    build_state2 = next(s for s in state2["stageStates"] if s["stageName"] == "Build")
    inbound2 = build_state2["inboundTransitionState"]
    assert inbound2["enabled"] is True, f"expected inbound transition re-enabled after EnableStageTransition, got enabled={inbound2['enabled']!r}"


# ===== helpers =====
_ROLE_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _bucket_policy_doc(bucket_name: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetBucketVersioning", "s3:PutObject"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                }
            ],
        }
    )


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    if ctx.region == "us-east-1":
        # create_bucket rejects an explicit LocationConstraint for us-east-1.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_object_versions(Bucket=name)
        for v in resp.get("Versions", []) + resp.get("DeleteMarkers", []):
            s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_pipeline_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_ROLE_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_name = "artifact-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=_bucket_policy_doc(bucket_name))

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_custom_action_type(ctx, category: str, provider: str, *, input_range=(0, 0), output_range=(0, 0)) -> dict[str, str]:
    cp = ctx.client("codepipeline")
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": input_range[0], "maximumCount": input_range[1]},
        outputArtifactDetails={"minimumCount": output_range[0], "maximumCount": output_range[1]},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version="1"))
    return {"category": category, "owner": "Custom", "provider": provider, "version": "1"}


def _worker_pipeline_stages(source_provider: str, build_provider: str) -> list[dict[str, Any]]:
    return [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "Source",
                    "actionTypeId": {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {},
                    "runOrder": 1,
                }
            ],
        },
        {
            "name": "Build",
            "actions": [
                {
                    "name": "Build",
                    "actionTypeId": {"category": "Build", "owner": "Custom", "provider": build_provider, "version": "1"},
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {},
                    "runOrder": 1,
                }
            ],
        },
    ]


def _safe_delete_pipeline(cp, name: str) -> None:
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _create_pipeline(ctx, pipeline_def: dict[str, Any], *, tags=None) -> dict[str, Any]:
    cp = ctx.client("codepipeline")
    if tags is None:
        tags = [{"key": "sim2real", "value": CHECK}]
    kwargs: dict[str, Any] = {"pipeline": pipeline_def, "tags": tags}
    last_err = None
    resp = None
    # Bounded retry, not a blind sleep: CreatePipeline reports InvalidStructureException /
    # ValidationException while the just-created role has not yet propagated to be assumable.
    for _ in range(6):
        try:
            resp = cp.create_pipeline(**kwargs)
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    name = pipeline_def["name"]
    ctx.on_cleanup(lambda: _safe_delete_pipeline(cp, name))
    return resp["pipeline"]


def _error_code(fn: Callable[[], Any]):
    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
