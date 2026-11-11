"""create-pipeline-duplicate-name-conflict-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pipeline-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePipeline reusing a live pipeline's name fails with PipelineNameInUseException
    without overwriting its definition; once that pipeline is deleted the identical call
    succeeds, so the live pipeline, not the name, is what is refused."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _upload_source_zip(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-dupname-")

    pipeline_tags = [{"key": "sim2real", "value": CHECK}]
    original_def = _two_stage_pipeline(name, role_arn, bucket, key)
    created = _wait_role_usable(
        lambda: cp.create_pipeline(pipeline=original_def, tags=pipeline_tags)
    )["pipeline"]
    assert created["version"] == 1, f"expected positive control to create version 1, got {created['version']}"
    ctx.on_cleanup(lambda: _safe_delete_pipeline(cp, name))

    # Attempt to "recreate" the same pipeline name with a materially different
    # definition (different role) -- must be rejected, not silently applied.
    conflicting_def = json.loads(json.dumps(original_def))
    conflicting_def["stages"][1]["name"] = "SomethingElseEntirely"

    code, message = _error(lambda: cp.create_pipeline(pipeline=conflicting_def))
    assert code == "PipelineNameInUseException", f"expected PipelineNameInUseException, got {code!r}"
    assert message == f"A pipeline with the name '{name}' already exists in account '{ctx.account}'", (
        f"unexpected name-in-use message: {message!r}"
    )

    # Effect absent: the original pipeline definition/version must be unchanged.
    after = cp.get_pipeline(name=name)["pipeline"]
    assert after["version"] == 1, f"expected version to remain 1 after the rejected conflict, got {after['version']}"
    assert after["stages"][1]["name"] == "Approve", (
        f"expected stage[1] to remain 'Approve' after the rejected conflict, got {after['stages'][1]['name']!r}"
    )

    # Restore: free the name by deleting the original pipeline. GetPipeline by name
    # then raises PipelineNotFoundException -- only a deleted pipeline's absence, not
    # the name string, was ever the obstacle.
    cp.delete_pipeline(name=name)
    deleted_code, deleted_message = _error(lambda: cp.get_pipeline(name=name))
    assert deleted_code == "PipelineNotFoundException", (
        f"expected PipelineNotFoundException after deleting the original, got {deleted_code!r}"
    )
    assert deleted_message == f"Account '{ctx.account}' does not have a pipeline with name '{name}'", (
        f"unexpected not-found message after deleting the original: {deleted_message!r}"
    )

    # The identical call now succeeds: the live pipeline was the obstacle, not the name.
    restored = _wait_role_usable(
        lambda: cp.create_pipeline(pipeline=original_def, tags=pipeline_tags)
    )["pipeline"]
    assert restored["name"] == name, f"expected restored pipeline name {name!r}, got {restored['name']!r}"
    assert restored["version"] == 1, f"expected restored pipeline to start at version 1, got {restored['version']}"

    restored_get = cp.get_pipeline(name=name)["pipeline"]
    assert restored_get["stages"][1]["name"] == "Approve", (
        f"expected restored stage[1] to be 'Approve', got {restored_get['stages'][1]['name']!r}"
    )


# ===== helpers =====


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_pipeline(cp, name: str) -> None:
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket; every other
    # region requires one. This branches on the S3 API contract, not on a pinned region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        # An execution started by CreatePipeline can still be writing artifacts after the
        # pipeline is deleted, so empty and delete in a bounded loop.
        deadline = time.monotonic() + 90.0
        while True:
            resp = s3.list_object_versions(Bucket=bucket)
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            try:
                s3.delete_bucket(Bucket=bucket)
                return
            except ClientError as err:
                if err.response["Error"]["Code"] != "BucketNotEmpty" or time.monotonic() > deadline:
                    raise
            time.sleep(5)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_source_zip(ctx, bucket: str, key: str = "source.zip") -> str:
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real-behavioral-source")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return key


def _create_pipeline_role(ctx, bucket: str) -> str:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cp-policy-")
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
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _wait_role_usable(fn, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in (
                "InvalidStructureException",
                "InvalidParameterValueException",
                "InvalidRoleException",
            ) or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _two_stage_pipeline(name: str, role_arn: str, bucket: str, source_key: str) -> dict:
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
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
                        "outputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": {
                            "S3Bucket": bucket,
                            "S3ObjectKey": source_key,
                            "PollForSourceChanges": "false",
                        },
                        "runOrder": 1,
                    }
                ],
            },
            {
                "name": "Approve",
                "actions": [
                    {
                        "name": "ApprovalAction",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                        "runOrder": 1,
                    }
                ],
            },
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
