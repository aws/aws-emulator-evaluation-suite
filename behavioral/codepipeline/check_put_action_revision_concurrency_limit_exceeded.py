"""put-action-revision-concurrency-limit-exceeded."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-action-revision-concurrency-limit-exceeded"
GROUP = "concurrency"
SERVICES = ["codepipeline"]

# Fixed, non-adjustable "Active executions per pipeline" quota for PARALLEL-mode
# pipelines: https://docs.aws.amazon.com/general/latest/gr/codepipeline.html
# Probed adaptively rather than hard-coded, capped well above the documented default so
# a missing limit fails loudly instead of looping forever.
_SEARCH_CEILING = 80
_QUOTA = 50


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutActionRevision with newRevision starts executions until a PARALLEL pipeline reaches its
    active-execution quota, the next call fails with ConcurrentPipelineExecutionsLimitExceededException and its
    exact message, and after a slot frees a call starts a new execution.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_type_id, _ = _register_source_action_type(ctx, cp)
    pipeline_name = _create_parallel_pipeline(ctx, cp, role_arn, bucket, source_type_id)

    # positive control: each distinct revision starts a genuinely new (InProgress, never
    # acked/completed) execution -- keep going until the concurrency quota rejects one
    exec_ids = []
    limit_code = None
    limit_message = None
    for i in range(_SEARCH_CEILING):
        try:
            resp = _call_with_backoff(lambda i=i: cp.put_action_revision(
                pipelineName=pipeline_name,
                stageName="Source",
                actionName="SourceAction",
                actionRevision=_action_revision(i),
            ))
        except ClientError as e:
            limit_code = e.response["Error"]["Code"]
            limit_message = e.response["Error"].get("Message")
            break
        assert resp["newRevision"] is True, resp
        exec_ids.append(resp["pipelineExecutionId"])
        time.sleep(0.2)

    assert limit_code == "ConcurrentPipelineExecutionsLimitExceededException", (
        f"never hit the concurrency limit after {len(exec_ids)} executions; last error code={limit_code}"
    )
    assert limit_message == (
        "The limit for concurrent pipeline executions has been exceeded. "
        "Wait for concurrent executions to complete, and then try again."
    ), limit_message
    assert len(set(exec_ids)) == len(exec_ids), "duplicate execution ids returned"
    assert len(exec_ids) >= 1

    # effect absent: the rejected call did not create any execution beyond `exec_ids`
    # (tolerate a rare +1 discrepancy from an in-flight retry racing the limit check)
    executions = cp.list_pipeline_executions(pipelineName=pipeline_name, maxResults=100)["pipelineExecutionSummaries"]
    ids = {e["pipelineExecutionId"] for e in executions}
    assert set(exec_ids) <= ids, (set(exec_ids) - ids)
    assert len(ids) - len(exec_ids) <= 1, (len(ids), len(exec_ids))

    # restore: the ceiling is a live count, not a permanent ban -- freeing slots below the
    # quota must let an otherwise-identical PutActionRevision succeed again.
    # The execution reaching Stopped and the concurrency counter releasing its slot are
    # NOT the same event -- real AWS lags the counter behind the status, so the retry
    # below tolerates a further ConcurrentPipelineExecutionsLimitExceededException
    # instead of treating the first one as proof the slot never freed.
    # The execution CreatePipeline starts is InProgress too, so more than 50 executions can be active at
    # the rejection: enough of this check's own are stopped to bring the active count below 50.
    active = _in_progress_ids(cp, pipeline_name)
    to_stop = [e for e in exec_ids if e in active][: max(1, len(active) - _QUOTA + 1)]
    for execution_id in to_stop:
        cp.stop_pipeline_execution(
            pipelineName=pipeline_name, pipelineExecutionId=execution_id, abandon=True,
            reason="sim2real-free-concurrency-slot",
        )
    for execution_id in to_stop:
        _wait_for_status(cp, pipeline_name, execution_id, "Stopped")
    restored_resp = _retry_until_slot_frees(cp, pipeline_name, len(exec_ids))
    assert restored_resp["newRevision"] is True, restored_resp
    assert restored_resp["pipelineExecutionId"] not in exec_ids, "restore call reused an old execution id"


def _in_progress_ids(cp, pipeline_name: str) -> set[str]:
    ids: set[str] = set()
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=pipeline_name):
        ids.update(
            s["pipelineExecutionId"] for s in page["pipelineExecutionSummaries"] if s["status"] == "InProgress"
        )
    return ids


def _retry_until_slot_frees(cp, pipeline_name: str, revision_index: int, timeout_s: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout_s
    delay = 2.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cp.put_action_revision(
                pipelineName=pipeline_name,
                stageName="Source",
                actionName="SourceAction",
                actionRevision=_action_revision(revision_index),
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ConcurrentPipelineExecutionsLimitExceededException", "ThrottlingException"):
                last_err = e
                time.sleep(delay)
                delay = min(delay * 1.5, 10.0)
                continue
            raise
    raise AssertionError(
        f"stopping an execution never freed a concurrency slot within {timeout_s}s: {last_err}"
    )


def _wait_for_status(cp, pipeline_name: str, execution_id: str, want: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cp.get_pipeline_execution(
            pipelineName=pipeline_name, pipelineExecutionId=execution_id
        )["pipelineExecution"]["status"]
        if last == want:
            return
        time.sleep(1.5)
    raise AssertionError(f"execution {execution_id} never reached {want!r}, last status={last!r}")


def _action_revision(i: int) -> dict:
    return {
        "revisionId": f"rev-{i}",
        "revisionChangeId": f"chg-{i}",
        "created": datetime.now(timezone.utc),
    }


def _call_with_backoff(fn, max_attempts: int = 8):
    delay = 1.0
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] == "ThrottlingException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 15.0)
                continue
            raise


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
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


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:GetBucketVersioning", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="artifact-access", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="artifact-access"))
    return role_arn


def _register_source_action_type(ctx, cp) -> tuple[dict, str]:
    provider = ctx.unique_name("CustSrc-")[:35]
    cp.create_custom_action_type(
        category="Source",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Source", provider=provider, version="1"))
    return {"category": "Source", "owner": "Custom", "provider": provider, "version": "1"}, provider


def _create_parallel_pipeline(ctx, cp, role_arn: str, bucket: str, source_type_id: dict) -> str:
    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")
    definition = {
        "name": pipeline_name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "executionMode": "PARALLEL",
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": source_type_id,
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }],
            },
            {
                "name": "Approve",
                "actions": [{
                    "name": "ApproveAction",
                    "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                }],
            },
        ],
    }
    _create_pipeline_with_retry(cp, definition)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))
    return pipeline_name


def _create_pipeline_with_retry(cp, definition: dict, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(pipeline=definition, tags=[{"key": "sim2real-check", "value": CHECK}])
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"create_pipeline never succeeded (role propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
