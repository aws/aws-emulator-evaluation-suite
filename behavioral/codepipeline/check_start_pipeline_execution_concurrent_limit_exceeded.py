"""start-pipeline-execution-concurrent-limit-exceeded."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-pipeline-execution-concurrent-limit-exceeded"
GROUP = "concurrency"
SERVICES = ["codepipeline"]

_SCENARIO = "cp-start-pipeline-execution-concurrent-limit-exceeded"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PARALLEL-mode pipeline filled to 50 active executions rejects the next StartPipelineExecution with
    ConcurrentPipelineExecutionsLimitExceededException and its exact message, and exactly 50 executions remain
    active.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _put_source_object(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-limit-")
    # Approval action is never approved during the fill, so every execution stays
    # active (InProgress) instead of draining -- PARALLEL mode runs each independently.
    stages = [_source_stage(bucket, key), _approval_stage("Gate", "Approve")]
    _create_pipeline(ctx, name, role_arn, bucket, stages, execution_mode="PARALLEL")

    # CreatePipeline auto-triggers an initial execution against the pipeline it just
    # made, and that execution occupies one of the 50 active slots. Wait for the execution list to
    # stop changing (two consecutive identical reads) before baselining against it,
    # bounded so a pipeline with no auto-trigger doesn't wait out the full window,
    # then fill only as many more as the cap has room for.
    ids_before = _stable_execution_ids(cp, name)
    fill_target = 50 - len(ids_before)
    assert fill_target > 0, (
        f"baseline already holds {len(ids_before)} active executions -- nothing left to fill toward the cap of 50"
    )

    # Issue the fill sequentially, one at a time with a pacing gap: firing many
    # starts in a burst trips CodePipeline's own request-rate throttle before the
    # business concurrency limit, which is a different exception than the one
    # under test.
    exec_ids = []
    for _ in range(fill_target):
        exec_ids.append(_start_with_backoff(cp, name))
        time.sleep(1.0)
    assert len(exec_ids) == fill_target, f"expected {fill_target} successful starts, got {len(exec_ids)}"
    assert set(exec_ids).isdisjoint(ids_before), (
        f"newly started execution ids overlapped the baseline: {set(exec_ids) & ids_before}"
    )

    def _one_too_many():
        return _start_with_backoff(cp, name)

    err = _error(_one_too_many)
    assert err["Code"] == "ConcurrentPipelineExecutionsLimitExceededException", (
        f"expected ConcurrentPipelineExecutionsLimitExceededException for the 51st active execution, got {err!r}"
    )
    expected = "The limit for concurrent pipeline executions has been exceeded. Please try again later."
    assert err.get("Message") == expected, (err.get("Message"), expected)

    # Effect absent: no execution beyond the fill was created, and the cap sits at
    # exactly 50 total (baseline + fill), never 51.
    all_ids = {s["pipelineExecutionId"] for s in _paginate_executions(cp, name)}
    new_ids = all_ids - ids_before
    assert new_ids == set(exec_ids), f"executions beyond the fill: {new_ids - set(exec_ids)}"
    assert len(all_ids) == 50, f"expected exactly 50 active executions at the cap, found {len(all_ids)}"


def _start_with_backoff(cp, name, max_attempts: int = 10):
    delay = 0.5
    for attempt in range(max_attempts):
        try:
            return cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ThrottlingException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2.0, 10.0)
                continue
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _paginate_executions(cp, name):
    out = []
    token = None
    while True:
        kwargs = {"pipelineName": name, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = cp.list_pipeline_executions(**kwargs)
        out.extend(resp["pipelineExecutionSummaries"])
        token = resp.get("nextToken")
        if not token:
            break
    return out


def _stable_execution_ids(cp, name, timeout_s: float = 30.0, interval_s: float = 2.0) -> set[str]:
    deadline = time.monotonic() + timeout_s
    seen = None
    while True:
        current = {s["pipelineExecutionId"] for s in _paginate_executions(cp, name)}
        if current == seen or time.monotonic() >= deadline:
            return current
        seen = current
        time.sleep(interval_s)


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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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
    # No sleep here: IAM role propagation is eventually consistent with no fixed
    # window, so _create_pipeline's own bounded retry on ValidationException /
    # InvalidStructureException absorbs it instead of a blind wait.
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower()
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 (the one
    # region it will not accept naming itself); every other region requires it.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})

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
    # Bounded retry on ValidationException / InvalidStructureException: this is also
    # what absorbs IAM's eventually-consistent role propagation (see
    # _create_pipeline_role), since CodePipeline rejects a roleArn it cannot yet see.
    for _ in range(6):
        try:
            resp = cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": _SCENARIO}])
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
