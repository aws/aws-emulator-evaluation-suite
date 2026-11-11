"""pipeline-lifecycle-create-active-delete."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-lifecycle-create-active-delete"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePipeline yields a GetPipeline-visible active pipeline; DeletePipeline removes it
    and a subsequent GetPipeline/GetPipelineState both return PipelineNotFoundException."""
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")

    source_bucket = _create_bucket(ctx, "lifecycle-src")
    artifact_bucket = _create_bucket(ctx, "lifecycle-art")
    s3.put_object(Bucket=source_bucket, Key="app.zip", Body=_make_zip_bytes())

    role_arn = _create_pipeline_role(ctx, [source_bucket, artifact_bucket])

    name = ctx.unique_name("sim2real-cp-lifecycle-")
    pipeline_def = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [_source_stage(source_bucket, "app.zip"), _approval_stage()],
    }
    _create_pipeline_with_retry(cp, pipeline_def)
    _register_pipeline_cleanup(ctx, cp, name)

    got = cp.get_pipeline(name=name)
    assert got["pipeline"]["name"] == name, f"expected pipeline name {name!r}, got {got['pipeline']['name']!r}"
    assert got["pipeline"]["roleArn"] == role_arn, (
        f"expected roleArn {role_arn!r}, got {got['pipeline']['roleArn']!r}"
    )
    assert len(got["pipeline"]["stages"]) == 2, f"expected 2 stages, got {len(got['pipeline']['stages'])}"
    assert got["pipeline"]["version"] == 1, f"expected version 1 on first create, got {got['pipeline']['version']}"
    assert got["metadata"]["pipelineArn"].endswith(f":{name}"), (
        f"pipelineArn {got['metadata']['pipelineArn']!r} does not end with :{name}"
    )

    state = cp.get_pipeline_state(name=name)
    stage_names = {s["stageName"] for s in state["stageStates"]}
    assert stage_names == {"Source", "Approval"}, f"expected stage names Source/Approval, got {stage_names}"

    names = [p["name"] for p in cp.list_pipelines()["pipelines"]]
    assert name in names, f"expected {name!r} in ListPipelines, got {names}"

    cp.delete_pipeline(name=name)

    expected = ("PipelineNotFoundException", f"Account '{ctx.account}' does not have a pipeline with name '{name}'")
    get_refusal = _error_code(lambda: cp.get_pipeline(name=name))
    assert get_refusal == expected, (
        f"expected {expected!r} from GetPipeline after delete, got {get_refusal!r}"
    )

    state_refusal = _error_code(lambda: cp.get_pipeline_state(name=name))
    assert state_refusal == expected, (
        f"expected {expected!r} from GetPipelineState after delete, got {state_refusal!r}"
    )


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
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_pipeline_with_retry(cp, pipeline_def: dict) -> None:
    """IAM role/policy propagation is eventually consistent: CodePipeline can reject
    CreatePipeline with InvalidStructureException until it can assume the freshly-created
    role. Retry on that specific code, bounded, instead of guessing a fixed sleep."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidStructureException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


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


def _approval_stage() -> dict:
    return {
        "name": "Approval",
        "actions": [
            {
                "name": "ApprovalAction",
                "actionTypeId": {
                    "category": "Approval",
                    "owner": "AWS",
                    "provider": "Manual",
                    "version": "1",
                },
            }
        ],
    }


def _register_pipeline_cleanup(ctx, cp, name: str) -> None:
    def _cleanup():
        try:
            cp.delete_pipeline(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PipelineNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
