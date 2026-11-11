"""pipeline-execution-start-to-terminal-state."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-execution-start-to-terminal-state"
GROUP = "state-machine"
SERVICES = ["codepipeline"]
_SCENARIO = "codepipeline-execution-terminal-state"

_TERMINAL = {"Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartPipelineExecution transitions a fully-automatic S3-source/S3-deploy pipeline
    execution from InProgress to Succeeded, and the deploy bucket actually receives the
    extracted source object (real data-plane effect, not just a status flip)."""
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")

    source_bucket = _create_bucket(ctx, "term-src")
    artifact_bucket = _create_bucket(ctx, "term-art")
    deploy_bucket = _create_bucket(ctx, "term-dst")
    s3.put_object(Bucket=source_bucket, Key="app.zip", Body=_make_zip_bytes())
    role_arn = _create_pipeline_role(ctx, [source_bucket, artifact_bucket, deploy_bucket])

    name = ctx.unique_name("sim2real-cp-term-")
    pipeline_def = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [
            _source_stage(source_bucket, "app.zip"),
            _deploy_stage(deploy_bucket),
        ],
    }
    _create_pipeline_with_role_propagation(
        cp, pipeline_def, tags=[{"key": "sim2real", "value": _SCENARIO}], timeout_s=90.0
    )
    _register_pipeline_cleanup(ctx, cp, name)

    # CreatePipeline auto-starts an initial execution; let it fully settle before we
    # track our own explicit execution, so SUPERSEDED-mode races don't confuse the result.
    _poll_until(
        lambda: cp.list_pipeline_executions(pipelineName=name)["pipelineExecutionSummaries"],
        lambda execs: len(execs) >= 1 and execs[0]["status"] in _TERMINAL,
        timeout_s=180.0,
        interval_s=5.0,
    )

    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]

    execution = _poll_execution(
        cp, name, exec_id, lambda e: e["status"] in _TERMINAL, timeout_s=180.0, interval_s=5.0
    )
    assert execution["status"] == "Succeeded", (
        f"expected pipeline execution to reach Succeeded, got {execution['status']!r}"
    )

    state = cp.get_pipeline_state(name=name)
    stage_by_name = {s["stageName"]: s for s in state["stageStates"]}
    source_status = stage_by_name["Source"]["latestExecution"]["status"]
    assert source_status == "Succeeded", f"expected Source stage Succeeded, got {source_status!r}"
    deploy_status = stage_by_name["Deploy"]["latestExecution"]["status"]
    assert deploy_status == "Succeeded", f"expected Deploy stage Succeeded, got {deploy_status!r}"

    listing = s3.list_objects_v2(Bucket=deploy_bucket)
    keys = {obj["Key"] for obj in listing.get("Contents", [])}
    assert "app.txt" in keys, f"expected extracted app.txt in deploy bucket, got keys={keys!r}"


# ===== helpers =====

def _make_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.txt", "hello-codepipeline")
    return buf.getvalue()


def _create_bucket(ctx, suffix: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-cp-{suffix}-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]}
    )

    def _cleanup():
        try:
            versions = s3.list_object_versions(Bucket=name)
            to_delete = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
            ]
            if to_delete:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": to_delete}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _create_pipeline_role(ctx, bucket_names: list) -> str:
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]["Arn"]

    resources = []
    for b in bucket_names:
        resources.append(f"arn:aws:s3:::{b}")
        resources.append(f"arn:aws:s3:::{b}/*")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": resources}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _source_stage(bucket: str, key: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "SourceAction",
                "actionTypeId": {
                    "category": "Source",
                    "owner": "AWS",
                    "provider": "S3",
                    "version": "1",
                },
                "outputArtifacts": [{"name": "SourceArtifact"}],
                "configuration": {
                    "S3Bucket": bucket,
                    "S3ObjectKey": key,
                    "PollForSourceChanges": "false",
                },
            }
        ],
    }


def _deploy_stage(bucket: str) -> dict:
    return {
        "name": "Deploy",
        "actions": [
            {
                "name": "DeployAction",
                "actionTypeId": {
                    "category": "Deploy",
                    "owner": "AWS",
                    "provider": "S3",
                    "version": "1",
                },
                "inputArtifacts": [{"name": "SourceArtifact"}],
                "configuration": {"BucketName": bucket, "Extract": "true"},
            }
        ],
    }


def _create_pipeline_with_role_propagation(cp, pipeline_def: dict, tags=None, timeout_s: float = 90.0):
    """IAM role/policy propagation to CodePipeline's assume-role check is eventually
    consistent; retry CreatePipeline while it reports the fresh role as unassumable,
    instead of guessing a fixed wait."""
    kwargs: dict = {"pipeline": pipeline_def}
    if tags is not None:
        kwargs["tags"] = tags
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (
                err.get("Code") == "InvalidStructureException"
                and "AssumeRole" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _register_pipeline_cleanup(ctx, cp, name: str) -> None:
    def _cleanup():
        try:
            cp.delete_pipeline(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PipelineNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _poll_execution(cp, name, exec_id, predicate, timeout_s=180.0, interval_s=5.0):
    """Poll GetPipelineExecution, tolerating the brief propagation window right
    after StartPipelineExecution where the new execution id is not yet visible."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cp.get_pipeline_execution(
                pipelineName=name, pipelineExecutionId=exec_id
            )["pipelineExecution"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                time.sleep(interval_s)
                continue
            raise
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
