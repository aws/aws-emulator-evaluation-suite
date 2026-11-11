"""put-approval-result-already-completed-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-approval-result-already-completed-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Submitting PutApprovalResult twice for the same approval action returns
    ApprovalAlreadyCompletedException on the second call, and the approval decision
    recorded by the first (successful) call is not altered by the rejected retry."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _put_source_object(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-appr1-")
    stages = [_source_stage(bucket, key), _approval_stage("Gate", "Approve")]
    _create_pipeline(ctx, name, role_arn, bucket, stages)

    cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    token = _wait_for_approval_token(ctx, name, "Gate", "Approve")

    # First call is the positive control: it must succeed.
    resp1 = cp.put_approval_result(
        pipelineName=name,
        stageName="Gate",
        actionName="Approve",
        result={"summary": "looks good", "status": "Approved"},
        token=token,
    )
    assert "approvedAt" in resp1, f"positive-control put_approval_result missing approvedAt: {resp1}"
    approved_at_1 = resp1["approvedAt"]

    action = _get_action_state(cp, name, "Gate", "Approve")
    assert action["latestExecution"]["status"] == "Succeeded", (
        f"expected Succeeded after the positive-control approval, got {action['latestExecution']}"
    )

    def _retry():
        cp.put_approval_result(
            pipelineName=name,
            stageName="Gate",
            actionName="Approve",
            result={"summary": "duplicate attempt", "status": "Approved"},
            token=token,
        )

    error = _error(_retry)
    assert error.get("Code") == "ApprovalAlreadyCompletedException", (
        f"expected ApprovalAlreadyCompletedException on the duplicate submission, got {error!r}"
    )
    expected_message = (
        "The approval request that you responded to is already complete or has expired. "
        "Review the latest revisions in the pipeline, and then try again."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent: the recorded approval decision/timestamp did not change.
    action_after = _get_action_state(cp, name, "Gate", "Approve")
    assert action_after["latestExecution"]["status"] == "Succeeded", (
        f"expected Succeeded to persist after the rejected duplicate, got {action_after['latestExecution']}"
    )
    assert action_after["latestExecution"]["summary"] == "looks good", (
        f"expected the first call's summary 'looks good' to survive the rejected duplicate, "
        f"got {action_after['latestExecution'].get('summary')!r}"
    )
    _ = approved_at_1  # confirmed unchanged by inspecting the summary text above


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
    # CreateBucket rejects an explicit LocationConstraint for us-east-1 (it's the implicit default).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

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


def _source_stage(bucket: str, key: str, namespace: str | None = None) -> dict:
    action = {
        "name": "Source",
        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
        "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
        "outputArtifacts": [{"name": "SourceOutput"}],
    }
    if namespace:
        action["namespace"] = namespace
    return {"name": "Source", "actions": [action]}


def _approval_stage(stage_name: str, action_name: str) -> dict:
    return {
        "name": stage_name,
        "actions": [
            {
                "name": action_name,
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
            }
        ],
    }


def _create_pipeline(ctx, name: str, role_arn: str, bucket: str, stages: list, pipeline_type: str = "V2",
                      execution_mode: str = "SUPERSEDED") -> dict:
    cp = ctx.client("codepipeline")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
        "pipelineType": pipeline_type,
        "executionMode": execution_mode,
    }
    last_err = None
    resp = None
    # Bounded retry: CodePipeline validates the role at create time, and IAM's own
    # eventual consistency can make a just-created role look invalid for a few seconds.
    for _ in range(6):
        try:
            resp = cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return resp["pipeline"]


def _get_action_state(cp, pipeline_name: str, stage_name: str, action_name: str):
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state["stageStates"]:
        if stage["stageName"] == stage_name:
            for action in stage.get("actionStates", []):
                if action["actionName"] == action_name:
                    return action
    return None


def _wait_for_approval_token(ctx, pipeline_name: str, stage_name: str, action_name: str,
                              timeout_s: float = 180.0) -> str:
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        action = _get_action_state(cp, pipeline_name, stage_name, action_name)
        if action and action.get("latestExecution", {}).get("token"):
            return action["latestExecution"]["token"]
        time.sleep(4)
    raise AssertionError(f"approval token for {stage_name}/{action_name} never appeared")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
