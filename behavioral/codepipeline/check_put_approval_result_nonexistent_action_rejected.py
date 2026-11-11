"""put-approval-result-nonexistent-action-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-approval-result-nonexistent-action-rejected"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]

_SCENARIO = "codepipeline-put-approval-result-nonexistent-action-rejected"
# Real CodePipeline refuses an unknown action name inside a real stage with a message naming
# both the stage it searched and the action it could not find.
_MSG_BAD_ACTION = (
    "Approval does not include an action named NoSuchApprovalAction. "
    "Make sure you are using the correct name for the action, and then try again."
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutApprovalResult naming an action absent from the stage fails with ActionNotFoundException and its exact
    message, leaving the real approval InProgress with the same token, which then approves it.
    """
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    role_arn = _create_pipeline_role(ctx)
    bucket = _create_bucket(ctx, versioning=True)
    s3.put_object(Bucket=bucket, Key="src.txt", Body=b"hello-approval")

    name = ctx.unique_name("sim2real-cp-pipe-")
    _create_pipeline_with_retry(
        cp,
        {
            "name": name,
            "roleArn": role_arn,
            "artifactStore": {"type": "S3", "location": bucket},
            "stages": _minimal_stages(bucket, "src.txt", approval_action_name="Approve"),
        },
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    cp.start_pipeline_execution(name=name)

    action_state = _poll_until(
        lambda: _approval_action_state(cp, name),
        lambda a: a is not None
        and a.get("latestExecution", {}).get("status") == "InProgress"
        and "token" in a.get("latestExecution", {}),
        timeout_s=180,
        interval_s=5,
        description="approval action reaching InProgress with a token",
    )
    token = action_state["latestExecution"]["token"]

    code, msg = _error_code(
        lambda: cp.put_approval_result(
            pipelineName=name,
            stageName="Approval",
            actionName="NoSuchApprovalAction",
            result={"summary": "probe", "status": "Approved"},
            token=token,
        )
    )
    assert (code, msg) == ("ActionNotFoundException", _MSG_BAD_ACTION), (
        f"PutApprovalResult against an action absent from the stage must be refused as "
        f"ActionNotFoundException naming the stage and action, got {code!r} ({msg!r})"
    )

    # Effect absent: the real approval action is untouched, still awaiting the same token.
    unaffected = _approval_action_state(cp, name)
    assert unaffected["latestExecution"]["status"] == "InProgress", (
        f"the real approval action must stay InProgress after a rejected approval on a "
        f"nonexistent action name, got {unaffected['latestExecution']['status']!r}"
    )
    assert unaffected["latestExecution"]["token"] == token, (
        f"the real approval action's token must be unchanged by the rejected call: "
        f"expected {token!r}, got {unaffected['latestExecution'].get('token')!r}"
    )

    # Positive control: the correct action name with the same token approves it.
    cp.put_approval_result(
        pipelineName=name,
        stageName="Approval",
        actionName="Approve",
        result={"summary": "control-approve", "status": "Approved"},
        token=token,
    )
    _poll_until(
        lambda: _approval_action_state(cp, name),
        lambda a: a is not None and a.get("latestExecution", {}).get("status") == "Succeeded",
        timeout_s=60,
        interval_s=3,
        description="approval action transitioning to Succeeded after the control approval",
    )


def _create_pipeline_with_retry(cp, pipeline: dict, attempts: int = 6, delay_s: float = 5.0) -> dict:
    """CreatePipeline can transiently fail with InvalidStructureException /
    ValidationException while the just-created IAM role's trust policy propagates."""
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            return cp.create_pipeline(pipeline=pipeline)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message") or ""
    raise AssertionError(f"expected PutApprovalResult to be refused, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _approval_action_state(cp, name):
    state = cp.get_pipeline_state(name=name)
    for stage in state["stageStates"]:
        if stage["stageName"] == "Approval":
            for action in stage.get("actionStates", []):
                if action["actionName"] == "Approve":
                    return action
    return None


def _create_pipeline_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cp-policy-")
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_bucket(ctx, versioning: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-").lower()
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is CreateBucket's own historical special case: it rejects an explicit
    # LocationConstraint pointed at itself, so the constraint is only sent for every other region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    if versioning:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
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
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _minimal_stages(source_bucket, source_key, approval_action_name="Approve", approval_config=None):
    return [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                    "configuration": {
                        "S3Bucket": source_bucket,
                        "S3ObjectKey": source_key,
                        "PollForSourceChanges": "false",
                    },
                    "outputArtifacts": [{"name": "SourceArtifact"}],
                }
            ],
        },
        {
            "name": "Approval",
            "actions": [
                {
                    "name": approval_action_name,
                    "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                    "configuration": approval_config or {},
                }
            ],
        },
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
