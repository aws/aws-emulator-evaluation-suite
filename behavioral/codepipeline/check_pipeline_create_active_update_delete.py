"""pipeline-create-active-update-delete."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-create-active-update-delete"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created pipeline is immediately gettable, UpdatePipeline mutates its
    structure/version, and DeletePipeline makes it unreachable via GetPipeline."""
    cp = ctx.client("codepipeline")

    role_arn = _create_service_role(ctx)
    artifact_bucket = _create_bucket(ctx, versioned=False)
    source_bucket = _create_bucket(ctx, versioned=True)
    source_key = "src/app.zip"
    _put_zip_object(ctx, source_bucket, source_key, "app.txt", b"hello-cp-crud")

    name = ctx.unique_name("sim2real-cp-crud-")
    pipeline_decl = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "Source",
                        "actionTypeId": {
                            "category": "Source",
                            "owner": "AWS",
                            "provider": "S3",
                            "version": "1",
                        },
                        "outputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": {
                            "S3Bucket": source_bucket,
                            "S3ObjectKey": source_key,
                            "PollForSourceChanges": "false",
                        },
                    }
                ],
            },
            {
                "name": "Approval",
                "actions": [
                    {
                        "name": "Approve",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                    }
                ],
            },
        ],
    }

    create_resp = _create_pipeline_with_retry(
        cp, pipeline_decl, tags=[{"key": "sim2real", "value": name}]
    )

    def _cleanup_pipeline():
        try:
            cp.delete_pipeline(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PipelineNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_pipeline)

    assert create_resp["pipeline"]["version"] == 1, (
        f"expected initial version 1, got {create_resp['pipeline']['version']}"
    )

    # Immediately gettable / active. (CreatePipeline's response has no
    # "metadata" block -- only GetPipeline returns pipelineArn/created/updated.)
    got = cp.get_pipeline(name=name)
    assert got["pipeline"]["version"] == 1, f"expected version 1, got {got['pipeline']['version']}"
    stage_names = [s["name"] for s in got["pipeline"]["stages"]]
    assert stage_names == ["Source", "Approval"], f"expected [Source, Approval], got {stage_names}"
    arn = got["metadata"]["pipelineArn"]
    assert arn.endswith(f":{name}"), f"expected pipelineArn ending :{name}, got {arn}"

    # UpdatePipeline mutates the structure and bumps the version.
    updated_decl = dict(got["pipeline"])
    updated_decl.pop("version", None)
    updated_decl["stages"] = list(updated_decl["stages"]) + [
        {
            "name": "Approval2",
            "actions": [
                {
                    "name": "Approve2",
                    "actionTypeId": {
                        "category": "Approval",
                        "owner": "AWS",
                        "provider": "Manual",
                        "version": "1",
                    },
                }
            ],
        }
    ]
    update_resp = cp.update_pipeline(pipeline=updated_decl)
    assert update_resp["pipeline"]["version"] == 2, (
        f"expected version 2 after update, got {update_resp['pipeline']['version']}"
    )
    updated_stage_names = [s["name"] for s in update_resp["pipeline"]["stages"]]
    expected_stage_names = ["Source", "Approval", "Approval2"]
    assert updated_stage_names == expected_stage_names, (
        f"expected {expected_stage_names}, got {updated_stage_names}"
    )

    got_after_update = cp.get_pipeline(name=name)
    assert got_after_update["pipeline"]["version"] == 2, (
        f"expected version 2 on re-read, got {got_after_update['pipeline']['version']}"
    )
    assert len(got_after_update["pipeline"]["stages"]) == 3, (
        f"expected 3 stages on re-read, got {len(got_after_update['pipeline']['stages'])}"
    )

    # DeletePipeline makes it unreachable: an independent read 404s, and a mutation
    # against the dead id fails the same way rather than silently no-oping.
    cp.delete_pipeline(name=name)
    expected = (
        "PipelineNotFoundException",
        f"Account '{ctx.account}' does not have a pipeline with name '{name}'",
    )
    refusal = _error_code(lambda: cp.get_pipeline(name=name))
    assert refusal == expected, f"expected {expected!r}, got {refusal}"
    mutate_refusal = _error_code(
        lambda: cp.enable_stage_transition(
            pipelineName=name, stageName="Approval", transitionType="Inbound"
        )
    )
    assert mutate_refusal == expected, (
        f"expected {expected!r} on mutation of a deleted pipeline, got {mutate_refusal}"
    )


# ===== helpers =====


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _create_pipeline_with_retry(cp, pipeline_decl, tags=None):
    # IAM role/policy propagation into CodePipeline is eventually consistent with no
    # fixed documented window, so retry the create itself against the real signal
    # (InvalidStructureException/ValidationException while the role isn't assumable
    # yet) instead of guessing a sleep duration.
    kwargs = {"pipeline": pipeline_decl}
    if tags is not None:
        kwargs["tags"] = tags
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return cp.create_pipeline(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("InvalidStructureException", "ValidationException"):
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


def _zip_bytes(filename: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def _put_zip_object(ctx, bucket: str, key: str, filename: str, content: bytes) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=_zip_bytes(filename, content))


def _create_bucket(ctx, versioned: bool) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    if versioned:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        try:
            _empty_bucket(ctx, bucket)
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _create_service_role(ctx, extra_statements=None) -> str:
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
    )["Role"]

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    statements = [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]
    if extra_statements:
        statements.extend(extra_statements)
    policy = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
