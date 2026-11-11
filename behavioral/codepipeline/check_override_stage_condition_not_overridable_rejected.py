"""override-stage-condition-not-overridable-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "override-stage-condition-not-overridable-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """OverrideStageCondition on a condition with a Skip result fails with ConditionNotOverridableException and
    its exact message, twice, and the stage stays Skipped.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _put_source_object(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-cond-")

    mismatch_rule = {
        "name": "MismatchCheck",
        "ruleTypeId": {"category": "Rule", "owner": "AWS", "provider": "VariableCheck", "version": "1"},
        "configuration": {
            "Variable": "#{SourceVars.ETag}",
            "Value": "definitely-mismatched-value-xyz",
            "Operator": "EQ",
        },
    }
    stages = [
        _source_stage(bucket, key, namespace="SourceVars"),
        {
            "name": "GateSkip",
            "beforeEntry": {"conditions": [{"result": "SKIP", "rules": [mismatch_rule]}]},
            "actions": [_approval_action("ApproveSkip")],
        },
    ]
    _create_pipeline(ctx, name, role_arn, bucket, stages, tags=[{"key": "sim2real", "value": CHECK}])

    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]

    _poll_until(
        lambda: _stage_state(cp, name, "GateSkip"),
        lambda s: s is not None and s.get("latestExecution", {}).get("status") == "Skipped",
        timeout_s=240.0,
    )

    def _override_skip():
        cp.override_stage_condition(
            pipelineName=name, stageName="GateSkip", pipelineExecutionId=exec_id, conditionType="BEFORE_ENTRY"
        )

    refusal = _error_code(_override_skip)
    # AWS names the pipeline, not the execution id, in the "execution '...'" slot.
    assert refusal == (
        "ConditionNotOverridableException",
        f"The condition type BEFORE_ENTRY in stage GateSkip cannot be overridden now. Either it contains no "
        f"failed or in-progress rule, the execution '{name}' is already superseded, or the "
        f"pipeline definition has changed since the rules(s) failed.",
    ), refusal

    # Effect absent: the stage stays Skipped -- the override did not change it.
    stage_after = _stage_state(cp, name, "GateSkip")
    assert stage_after["latestExecution"]["status"] == "Skipped"

    # Overly-permissive check on a nonexistent condition type / stage combination:
    # overriding a stage that has no condition of the requested type at all is
    # also rejected, never silently accepted.
    def _override_nonexistent_condition():
        cp.override_stage_condition(
            pipelineName=name, stageName="GateSkip", pipelineExecutionId=exec_id, conditionType="ON_SUCCESS"
        )

    refusal2 = _error_code(_override_nonexistent_condition)
    assert refusal2 == (
        "ConditionNotOverridableException",
        f"The condition type ON_SUCCESS in stage GateSkip cannot be overridden now. Either it contains no "
        f"failed or in-progress rule, the execution '{name}' is already superseded, or the "
        f"pipeline definition has changed since the rules(s) failed.",
    ), refusal2


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last}")


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.txt", b"hello-sim2real")
    return buf.getvalue()


def _create_pipeline_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codepipeline.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:PutObject",
                        "s3:GetBucketVersioning",
                        "s3:ListBucket",
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                }
            ],
        }
    )
    policy_name = "artifact-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower()
    # S3 rejects a LocationConstraint of us-east-1 specifically; this is a comparison
    # against ctx.region, not a hardcoded target region (checks run in us-west-2).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        versions = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_source_object(ctx, bucket: str, key: str = "source.zip") -> str:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=_zip_bytes())
    return key


def _source_stage(bucket: str, key: str, namespace: str) -> dict:
    action = {
        "name": "Source",
        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
        "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
        "outputArtifacts": [{"name": "SourceOutput"}],
        "namespace": namespace,
    }
    return {"name": "Source", "actions": [action]}


def _approval_action(action_name: str) -> dict:
    return {
        "name": action_name,
        "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
    }


def _create_pipeline(ctx, name: str, role_arn: str, bucket: str, stages: list, pipeline_type: str = "V2",
                      execution_mode: str = "SUPERSEDED", tags: list | None = None) -> dict:
    cp = ctx.client("codepipeline")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
        "pipelineType": pipeline_type,
        "executionMode": execution_mode,
    }
    kwargs: dict = {"pipeline": pipeline}
    if tags is not None:
        kwargs["tags"] = tags
    last_err = None
    resp = None
    for _ in range(6):
        try:
            resp = cp.create_pipeline(**kwargs)
            break
        except ClientError as err:
            last_err = err
            # The role and its inline policy were just created; IAM propagation lags
            # CreatePipeline's own role-assumability validation, which surfaces here as
            # InvalidStructureException/ValidationException. Bounded retry, not a sleep.
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return resp["pipeline"]


def _stage_state(cp, pipeline_name: str, stage_name: str):
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state["stageStates"]:
        if stage["stageName"] == stage_name:
            return stage
    return None


def _get_action_state(cp, pipeline_name: str, stage_name: str, action_name: str):
    stage = _stage_state(cp, pipeline_name, stage_name)
    if not stage:
        return None
    for action in stage.get("actionStates", []):
        if action["actionName"] == action_name:
            return action
    return None


def _wait_for_approval_token(ctx, pipeline_name: str, stage_name: str, action_name: str,
                              timeout_s: float = 240.0) -> str:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        action = _get_action_state(cp, pipeline_name, stage_name, action_name)
        if action and action.get("latestExecution", {}).get("token"):
            return action["latestExecution"]["token"]
        time.sleep(5)
    raise AssertionError(f"approval token for {stage_name}/{action_name} never appeared")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
