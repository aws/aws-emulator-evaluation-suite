"""start-pipeline-execution-idempotent-client-request-token."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-pipeline-execution-idempotent-client-request-token"
GROUP = "concurrency"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two StartPipelineExecution calls with the same clientRequestToken return one pipelineExecutionId and add
    one execution, while a fresh token starts a distinct execution that ListPipelineExecutions shows.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _put_source_object(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-idem-")
    stages = [_source_stage(bucket, key), _approval_stage("Gate", "Approve")]
    _create_pipeline(ctx, name, role_arn, bucket, stages)

    # The pipeline-creation auto-triggered initial execution takes an unbounded
    # amount of time to land in ListPipelineExecutions; wait for the list to go
    # quiet (two consecutive identical reads) rather than guessing a duration.
    ids_before = _stable_execution_ids(cp, name)

    token = ctx.unique_name("sim2real-token-")
    exec_a = cp.start_pipeline_execution(name=name, clientRequestToken=token)["pipelineExecutionId"]
    exec_b = cp.start_pipeline_execution(name=name, clientRequestToken=token)["pipelineExecutionId"]
    assert exec_a == exec_b, "expected the repeated clientRequestToken to dedupe to one execution"

    # ListPipelineExecutions is eventually consistent with a just-started execution (a read
    # right after StartPipelineExecution can omit exec_a), so poll for exec_a to appear.
    ids_after_dup = _poll_until(
        lambda: {e["pipelineExecutionId"] for e in cp.list_pipeline_executions(pipelineName=name)
                 ["pipelineExecutionSummaries"]},
        lambda ids: exec_a in ids,
    )
    new_ids = ids_after_dup - ids_before
    assert new_ids == {exec_a}, f"expected exactly one new execution from the duplicated token, got {new_ids}"

    # Positive control: a different token creates a genuinely new, distinct execution.
    other_token = ctx.unique_name("sim2real-token-")
    exec_c = cp.start_pipeline_execution(name=name, clientRequestToken=other_token)["pipelineExecutionId"]
    assert exec_c != exec_a, f"expected a fresh clientRequestToken to start a new execution, got {exec_c} again"
    ids_after_new = _poll_until(
        lambda: {e["pipelineExecutionId"] for e in cp.list_pipeline_executions(pipelineName=name)
                 ["pipelineExecutionSummaries"]},
        lambda ids: exec_c in ids,
    )
    assert exec_c in ids_after_new, f"expected {exec_c} to appear in ListPipelineExecutions, got {ids_after_new}"
    assert (ids_after_new - ids_after_dup) == {exec_c}, (
        f"expected the fresh token to add exactly {exec_c}, got delta {ids_after_new - ids_after_dup}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _stable_execution_ids(cp, name: str, *, deadline_s: float = 40.0, interval_s: float = 4.0) -> set:
    """Poll ListPipelineExecutions until two consecutive reads agree, bounding the
    otherwise-unpredictable settle time of the create-triggered initial execution."""
    deadline = time.monotonic() + deadline_s
    previous = None
    while time.monotonic() < deadline:
        current = {e["pipelineExecutionId"] for e in cp.list_pipeline_executions(pipelineName=name)
                   ["pipelineExecutionSummaries"]}
        if current == previous:
            return current
        previous = current
        time.sleep(interval_s)
    raise TimeoutError(f"pipeline execution list for {name} never stabilized within {deadline_s}s")


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
    # No fixed wait here: CreatePipeline's own retry loop below already absorbs
    # IAM's eventual consistency with a bounded, stated-reason retry.
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower()
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


def _source_stage(bucket: str, key: str) -> dict:
    action = {
        "name": "Source",
        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
        "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
        "outputArtifacts": [{"name": "SourceOutput"}],
    }
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
    for _ in range(6):
        try:
            resp = cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as err:
            last_err = err
            # IAM role/trust propagation is eventually consistent: CodePipeline can
            # reject a just-created role with either code before it becomes visible.
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return resp["pipeline"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
