"""pipeline-lifecycle-delete-then-404."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-lifecycle-delete-then-404"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeletePipeline, GetPipeline and GetPipelineState must raise
    PipelineNotFoundException rather than returning stale/success data -- verified
    against a positive control (both calls succeed before deletion)."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    action_type_id = _register_custom_action(ctx, category="Build")
    pipeline_name = _create_pipeline(
        ctx,
        role_arn,
        bucket,
        stages=[
            _source_stage(bucket),
            {
                "name": "Build",
                "actions": [
                    {
                        "name": "Build",
                        "actionTypeId": action_type_id,
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "runOrder": 1,
                    }
                ],
            },
        ],
    )

    # Positive control: both reads succeed while the pipeline exists.
    get_name = cp.get_pipeline(name=pipeline_name)["pipeline"]["name"]
    assert get_name == pipeline_name, f"expected GetPipeline to echo {pipeline_name!r}, got {get_name!r}"
    state_name = cp.get_pipeline_state(name=pipeline_name)["pipelineName"]
    assert state_name == pipeline_name, f"expected GetPipelineState to echo {pipeline_name!r}, got {state_name!r}"

    cp.delete_pipeline(name=pipeline_name)
    # The registered cleanup below re-attempts DeletePipeline and silently no-ops since
    # the pipeline is already gone (see _create_pipeline's cleanup, which swallows errors).

    read_expected = ("PipelineNotFoundException", f"Account '{ctx.account}' does not have a pipeline with name '{pipeline_name}'")
    get_refusal = _error_code(lambda: cp.get_pipeline(name=pipeline_name))
    assert get_refusal == read_expected, f"expected GetPipeline on deleted pipeline to raise {read_expected!r}, got {get_refusal!r}"
    state_refusal = _error_code(lambda: cp.get_pipeline_state(name=pipeline_name))
    assert state_refusal == read_expected, f"expected GetPipelineState on deleted pipeline to raise {read_expected!r}, got {state_refusal!r}"
    # A delete must also block mutation on the dead id, not just reads.
    start_expected = ("PipelineNotFoundException", f"Pipeline with name {pipeline_name} does not exist in account {ctx.account}.")
    start_refusal = _error_code(lambda: cp.start_pipeline_execution(name=pipeline_name))
    assert start_refusal == start_expected, f"expected StartPipelineExecution on deleted pipeline to raise {start_expected!r}, got {start_refusal!r}"


# ===== helpers =====

def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral check source artifact")
    return buf.getvalue()


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 is S3's legacy default region: CreateBucket rejects an explicit
    # LocationConstraint there, so the literal pins that region-specific quirk, not
    # an assumption about which region the check runs in.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=_zip_bytes())
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "artifact-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:GetBucketVersioning",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _register_custom_action(ctx, category="Build") -> dict:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("s2rW")[:35]
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))
    return {"category": category, "owner": "Custom", "provider": provider, "version": version}


def _source_stage(bucket: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "configuration": {
                    "S3Bucket": bucket,
                    "S3ObjectKey": "source.zip",
                    "PollForSourceChanges": "false",
                },
                "outputArtifacts": [{"name": "SourceOutput"}],
            }
        ],
    }


def _create_pipeline(ctx, role_arn: str, bucket: str, stages: list, pipeline_type=None) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pl-")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    if pipeline_type:
        pipeline["pipelineType"] = pipeline_type

    # CodePipeline validates that it can assume roleArn at creation time, so a role
    # that was just created can be rejected with InvalidStructureException until IAM's
    # eventual-consistency window closes. Retry only that specific, expected rejection.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": "true"}])
            break
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("InvalidStructureException", "ValidationException"):
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)

    def _cleanup_pipeline():
        try:
            cp.delete_pipeline(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PipelineNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_pipeline)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
