"""start-pipeline-execution-concurrency-limit-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-pipeline-execution-concurrency-limit-rejected"
GROUP = "concurrency"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Past the 50 active-executions quota (PARALLEL mode), StartPipelineExecution fails with
    ConcurrentPipelineExecutionsLimitExceededException rather than queueing without bound; AWS
    counts with a short lag, so 50 to 55 started executions are accepted."""
    cp = ctx.client("codepipeline")
    bucket = _create_source_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = _create_pipeline(
        ctx, role_arn, bucket, "source.zip", execution_mode="PARALLEL", pipeline_type="V2"
    )

    # positive control: a normal StartPipelineExecution call, nowhere near the
    # ceiling, succeeds and produces a real, independently observable execution
    control_exec_id = _start_with_throttle_retry(cp, name)["pipelineExecutionId"]
    control_status = _get_execution_status_with_retry(ctx, name, control_exec_id)
    assert control_status == "InProgress"

    # Start executions one at a time until the service refuses one: a parallel burst trips
    # request-rate throttling long before the active-execution ceiling, so each call retries
    # through throttling on its own and the loop stops at the first quota refusal.
    successes = 0
    limit_errors = 0
    limit_messages: set[str] = set()
    throttled = 0
    other_errors: list[str] = []
    for _ in range(80):
        try:
            _start_with_throttle_retry(cp, name, attempts=10)
            successes += 1
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ConcurrentPipelineExecutionsLimitExceededException":
                limit_errors += 1
                limit_messages.add(e.response["Error"].get("Message", ""))
                break
            if code in ("ThrottlingException", "TooManyRequestsException"):
                # a request-rate throttle that outlasts the local retries is tolerated; every
                # other error must be the quota-exceeded code
                throttled += 1
            else:
                other_errors.append(code)

    assert not other_errors, f"unexpected error codes while filling the pipeline: {other_errors}"
    assert limit_errors > 0, (
        f"never hit the concurrency ceiling while firing a burst of executions: "
        f"successes={successes} throttled={throttled} limit_errors={limit_errors}"
    )

    expected = "The limit for concurrent pipeline executions has been exceeded. Please try again later."
    assert limit_messages == {expected}, f"expected message {expected!r}, got {limit_messages!r}"

    # +1 for the auto-triggered execution CreatePipeline already started, +1 for
    # the control execution above, plus however many of the burst succeeded
    total_started = 2 + successes

    # effect absent: the rejected calls did not sneak extra executions in
    statuses: dict[str, str] = {}
    paginator = cp.get_paginator("list_pipeline_executions")
    for page in paginator.paginate(pipelineName=name):
        for summary in page["pipelineExecutionSummaries"]:
            statuses[summary["pipelineExecutionId"]] = summary["status"]
    assert len(statuses) == total_started

    # The refusal comes at the documented ceiling of 50 active executions. AWS counts the
    # active executions with a short lag and starts 51 to 53 before it refuses; the bound is the
    # ceiling plus a margin of five. A lagging count can only admit more, so no refusal comes
    # before 50 executions have started.
    active = sum(1 for status in statuses.values() if status in ("InProgress", "Stopping"))
    assert 50 <= total_started <= 55, (
        f"{total_started} executions started ({active} active) before the refusal; the "
        f"active-execution ceiling is 50"
    )


def _start_with_throttle_retry(cp, name: str, attempts: int = 5):
    for i in range(attempts):
        try:
            return cp.start_pipeline_execution(name=name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and i < attempts - 1:
                time.sleep(min(1.0 * (i + 1), 5.0))
                continue
            raise
    raise AssertionError("unreachable")


# ===== helpers =====
_SOURCE_STAGE = "Source"
_SOURCE_ACTION = "SourceAction"
_APPROVAL_STAGE = "Approval"
_APPROVAL_ACTION = "ApprovalAction"


def _create_source_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-src-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup() -> None:
        versions = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=b"PK\x05\x06" + b"\x00" * 18)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    # CodePipeline reports a not-yet-propagated role as structurally invalid: retry exactly
    # that refusal to a 60 s deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            cp.create_pipeline(pipeline=decl, tags=[{"key": "sim2real-check", "value": CHECK}])
            break
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("InvalidStructureException", "ValidationException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _get_execution_status_with_retry(
    ctx, pipeline_name: str, execution_id: str, timeout_s: float = 30.0, interval_s: float = 2.0
) -> str:
    """GetPipelineExecution called immediately after StartPipelineExecution can
    transiently 404 while the execution record propagates; retry briefly."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)
            return resp["pipelineExecution"]["status"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
