"""start-pipeline-execution-concurrency-limit-exceeded."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-pipeline-execution-concurrency-limit-exceeded"
GROUP = "concurrency"
SERVICES = ["codepipeline"]
_LIMIT_MESSAGE = "The limit for concurrent pipeline executions has been exceeded. Please try again later."

# CodePipeline's "Active executions per pipeline" quota is a fixed 50 for PARALLEL-mode
# pipelines and is documented as non-adjustable:
# https://docs.aws.amazon.com/general/latest/gr/codepipeline.html (Service quotas)
# We probe adaptively (rather than hard-coding 50) issuing requests SEQUENTIALLY --
# AWS's own limit bookkeeping is not strictly serializable for truly simultaneous
# requests, so firing them one at a time (like PutActionRevision does) is what reliably
# trips the limit -- and cap the search well above the documented default so a missing
# limit fails loudly instead of looping forever.
_SEARCH_CEILING = 55


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Starting more concurrent executions than a PARALLEL-mode pipeline's active
    execution quota allows fails with ConcurrentPipelineExecutionsLimitExceededException
    instead of silently queuing the extra execution."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_type_id, _ = _register_source_action_type(ctx, cp)
    pipeline_name = _create_parallel_pipeline(ctx, cp, role_arn, bucket, source_type_id)

    # CodePipeline auto-triggers an initial execution the moment the pipeline is
    # created. Baseline
    # against that instead of guessing when it lands: poll until two consecutive
    # reads agree (a freeze detector), bounded by a deadline, then count only
    # executions that come from OUR calls, not this uncounted one.
    ids_before = _settled_execution_ids(cp, pipeline_name)

    # positive control: keep starting new executions (each stays InProgress -- nobody
    # ever polls/acks/completes the Source job) until the account/pipeline concurrency
    # limit rejects one with ConcurrentPipelineExecutionsLimitExceededException.
    started = []
    limit_code = limit_message = None
    for _ in range(_SEARCH_CEILING):
        ok, value, message = _start_once(cp, pipeline_name)
        if not ok:
            limit_code, limit_message = value, message
            break
        started.append(value)
        time.sleep(1.0)

    assert limit_code == "ConcurrentPipelineExecutionsLimitExceededException", (
        f"never hit the concurrency limit after {len(started)} executions; last error code={limit_code}"
    )
    assert len(set(started)) == len(started), "duplicate execution ids returned"
    assert len(started) >= 1, "expected at least one execution to succeed before the limit"
    assert limit_message == _LIMIT_MESSAGE, limit_message

    # negative: confirm the limit is still enforced on a fresh attempt too
    ok, code, message = _start_once(cp, pipeline_name)
    assert not ok
    assert code == "ConcurrentPipelineExecutionsLimitExceededException", code
    assert message == _LIMIT_MESSAGE, message

    # effect absent: no more executions exist than the ones that actually succeeded,
    # once the pre-existing auto-triggered execution is excluded from the count
    # (tolerate a rare +1 discrepancy from an in-flight retry racing the limit check)
    executions = cp.list_pipeline_executions(pipelineName=pipeline_name, maxResults=100)["pipelineExecutionSummaries"]
    ids = {e["pipelineExecutionId"] for e in executions}
    new_ids = ids - ids_before
    assert set(started) <= new_ids, (set(started) - new_ids)
    assert len(new_ids) - len(started) <= 1, (len(new_ids), len(started))


def _settled_execution_ids(cp, pipeline_name: str, timeout_s: float = 20.0, interval_s: float = 2.0) -> set[str]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        current = {
            e["pipelineExecutionId"]
            for e in cp.list_pipeline_executions(pipelineName=pipeline_name, maxResults=100)["pipelineExecutionSummaries"]
        }
        if current == last:
            return current
        last = current
        time.sleep(interval_s)
    return last if last is not None else set()


def _start_once(cp, pipeline_name: str, max_attempts: int = 6):
    delay = 1.0
    for attempt in range(max_attempts):
        try:
            resp = cp.start_pipeline_execution(name=pipeline_name)
            return True, resp["pipelineExecutionId"], None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ThrottlingException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 8.0)
                continue
            return False, code, e.response["Error"].get("Message")
    return False, "ThrottlingException", None


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        tags=[{"key": "sim2real", "value": CHECK}],
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
            cp.create_pipeline(pipeline=definition, tags=[{"key": "sim2real", "value": CHECK}])
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
