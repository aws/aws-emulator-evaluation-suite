"""put-action-revision-concurrency-limit-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-action-revision-concurrency-limit-rejected"
GROUP = "concurrency"
SERVICES = ["codepipeline"]

# Fixed, non-adjustable "Active executions per pipeline" ceiling for PARALLEL-mode
# pipelines (50): https://docs.aws.amazon.com/general/latest/gr/codepipeline.html
# Capped well above that documented default so a missing limit fails loudly instead
# of looping forever.
_FILL_CEILING = 70


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once a PARALLEL pipeline reaches its active-execution ceiling (at least 50 InProgress: the check's own
    executions and at most the CreatePipeline-triggered one), PutActionRevision with a new revision fails with
    ConcurrentPipelineExecutionsLimitExceededException and its exact message and creates no execution."""
    cp = ctx.client("codepipeline")
    bucket = _create_source_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = _create_pipeline(
        ctx, role_arn, bucket, "source.zip", execution_mode="PARALLEL", pipeline_type="V2"
    )

    # positive control: PutActionRevision with a fresh revision, well under the
    # ceiling, triggers a real new execution
    control_resp = cp.put_action_revision(
        pipelineName=name,
        stageName=_SOURCE_STAGE,
        actionName=_SOURCE_ACTION,
        actionRevision={
            "revisionId": "sim2real-behavioral-rev-control",
            "revisionChangeId": "sim2real-behavioral-control",
            "created": datetime.now(timezone.utc),
        },
    )
    assert control_resp["newRevision"] is True, f"expected newRevision=True, got {control_resp}"
    assert "pipelineExecutionId" in control_resp, f"no pipelineExecutionId in {control_resp}"

    # Sequential calls: a concurrent StartPipelineExecution burst hits ThrottlingException
    # before the 50-execution limit is reached.
    exec_ids: set[str] = {control_resp["pipelineExecutionId"]}
    limit_code = None
    limit_message = None
    for i in range(_FILL_CEILING):
        try:
            resp = _put_revision_with_backoff(cp, name, f"fill-{i}")
        except ClientError as e:
            limit_code = e.response["Error"]["Code"]
            limit_message = e.response["Error"].get("Message")
            break
        assert resp["newRevision"] is True, f"expected newRevision=True, got {resp}"
        exec_ids.add(resp["pipelineExecutionId"])
        time.sleep(0.2)

    assert limit_code == "ConcurrentPipelineExecutionsLimitExceededException", (
        f"never hit the concurrency ceiling after {len(exec_ids)} executions; last error code={limit_code}"
    )
    assert limit_message == _LIMIT_MESSAGE, limit_message

    # The quota is 50; the execution CreatePipeline starts is InProgress too, so at least 50 are active.
    in_progress = _in_progress_summaries(cp, name)
    active = len(in_progress)
    assert active >= 50, f"the ceiling rejected a revision with only {active} InProgress executions; expected >= 50"
    others = [s for s in in_progress if s["pipelineExecutionId"] not in exec_ids]
    stray = [s for s in others if (s.get("trigger") or {}).get("triggerType") != "CreatePipeline"]
    assert not stray and len(others) <= 1, (
        f"InProgress executions besides this check's revisions and the CreatePipeline one: {others}"
    )
    before_count = _count_executions(cp, name)

    code, message = _error(
        lambda: cp.put_action_revision(
            pipelineName=name,
            stageName=_SOURCE_STAGE,
            actionName=_SOURCE_ACTION,
            actionRevision={
                "revisionId": "sim2real-behavioral-rev-over-limit",
                "revisionChangeId": "sim2real-behavioral-over-limit",
                "created": datetime.now(timezone.utc),
            },
        )
    )
    assert code == "ConcurrentPipelineExecutionsLimitExceededException", f"expected the concurrency-limit code, got {code}"
    assert message == _LIMIT_MESSAGE, message

    # effect absent: the rejected call did not sneak an extra execution in
    after_count = _count_executions(cp, name)
    assert after_count == before_count, f"expected before={before_count} after={after_count} to be equal"


def _count_executions(cp, name: str) -> int:
    ids: set[str] = set()
    paginator = cp.get_paginator("list_pipeline_executions")
    for page in paginator.paginate(pipelineName=name):
        for summary in page["pipelineExecutionSummaries"]:
            ids.add(summary["pipelineExecutionId"])
    return len(ids)


def _in_progress_summaries(cp, name: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        found.extend(s for s in page["pipelineExecutionSummaries"] if s["status"] == "InProgress")
    return found


def _put_revision_with_backoff(cp, name: str, tag: str, attempts: int = 8):
    delay = 1.0
    for i in range(attempts):
        try:
            return cp.put_action_revision(
                pipelineName=name,
                stageName=_SOURCE_STAGE,
                actionName=_SOURCE_ACTION,
                actionRevision={
                    "revisionId": f"sim2real-behavioral-rev-{tag}",
                    "revisionChangeId": f"sim2real-behavioral-{tag}",
                    "created": datetime.now(timezone.utc),
                },
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and i < attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 15.0)
                continue
            raise
    raise AssertionError("unreachable")


_BUCKET_DRAIN_BUDGET_S = 60.0
_SOURCE_STAGE = "Source"
_SOURCE_ACTION = "SourceAction"
_APPROVAL_STAGE = "Approval"
_APPROVAL_ACTION = "ApprovalAction"


_LIMIT_MESSAGE = (
    "The limit for concurrent pipeline executions has been exceeded. "
    "Wait for concurrent executions to complete, and then try again."
)


def _error(fn):
    """The (code, message) of the ClientError fn() raises; a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded: {result!r}")


def _create_source_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-src-")
    # us-east-1 is a CreateBucket API quirk (rejects LocationConstraint), not a region pin
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        # Executions of the deleted pipeline can still write artifact versions, so every page is drained and
        # BucketNotEmpty is retried every 2 s until _BUCKET_DRAIN_BUDGET_S.
        deadline = time.monotonic() + _BUCKET_DRAIN_BUDGET_S
        while True:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
                objs += [
                    {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
                ]
                if objs:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            try:
                s3.delete_bucket(Bucket=bucket)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "BucketNotEmpty" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=b"PK\x05\x06" + b"\x00" * 18)
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
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
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
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
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    # no fixed settle here: _create_pipeline's own bounded retry loop absorbs IAM
    # role/policy propagation delay by retrying create_pipeline itself
    return role_arn


def _pipeline_declaration(
    name: str, role_arn: str, bucket: str, key: str,
    execution_mode: str | None, pipeline_type: str | None,
) -> dict[str, Any]:
    decl: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": _SOURCE_STAGE,
                "actions": [
                    {
                        "name": _SOURCE_ACTION,
                        "actionTypeId": {
                            "category": "Source", "owner": "AWS", "provider": "S3", "version": "1",
                        },
                        "configuration": {
                            "S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false",
                        },
                        "outputArtifacts": [{"name": "SourceOutput"}],
                    }
                ],
            },
            {
                "name": _APPROVAL_STAGE,
                "actions": [
                    {
                        "name": _APPROVAL_ACTION,
                        "actionTypeId": {
                            "category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1",
                        },
                    }
                ],
            },
        ],
    }
    if execution_mode:
        decl["executionMode"] = execution_mode
    if pipeline_type:
        decl["pipelineType"] = pipeline_type
    return decl


def _create_pipeline(
    ctx, role_arn: str, bucket: str, key: str,
    execution_mode: str | None = None, pipeline_type: str | None = None,
) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pipe-")
    decl = _pipeline_declaration(name, role_arn, bucket, key, execution_mode, pipeline_type)
    # A fresh role is not assumable by CodePipeline until IAM propagates it; retry only the
    # InvalidStructureException that reports the unassumable role, every 2 s to a 60 s deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            cp.create_pipeline(pipeline=decl, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as e:
            error = e.response["Error"]
            propagating = error["Code"] == "InvalidStructureException" and "AssumeRole" in error.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _get_action_state(ctx, pipeline_name: str, stage_name: str, action_name: str) -> dict[str, Any] | None:
    cp = ctx.client("codepipeline")
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state.get("stageStates", []):
        if stage["stageName"] == stage_name:
            for action in stage.get("actionStates", []):
                if action["actionName"] == action_name:
                    return action
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
