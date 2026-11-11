"""artifact-store-empty-vs-absent-field-preserved."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "artifact-store-empty-vs-absent-field-preserved"
GROUP = "representation"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pipeline variable with an empty-string description and one with no description stay
    distinguishable across CreatePipeline/UpdatePipeline/GetPipeline round trips."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _upload_source_zip(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-emptyabsent-")

    # ArtifactStore.encryptionKey is an all-or-nothing object and action configuration values
    # have minimum length 1; PipelineVariableDeclaration.description (V2 only) allows "".
    pipeline_def = _pipeline_with_variable_variants(
        name, role_arn, bucket, key, empty_var="VarEmptyDesc", absent_var="VarAbsentDesc"
    )
    _wait_role_usable(
        lambda: cp.create_pipeline(
            pipeline=pipeline_def, tags=[{"key": "sim2real", "value": CHECK}]
        )
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    created = cp.get_pipeline(name=name)["pipeline"]
    _assert_distinguishable(created, empty_var="VarEmptyDesc", absent_var="VarAbsentDesc")

    # Swap which variable carries the empty description vs the absent key, then update.
    swapped_def = _pipeline_with_variable_variants(
        name, role_arn, bucket, key, empty_var="VarAbsentDesc", absent_var="VarEmptyDesc"
    )
    cp.update_pipeline(pipeline=swapped_def)
    updated = cp.get_pipeline(name=name)["pipeline"]
    _assert_distinguishable(updated, empty_var="VarAbsentDesc", absent_var="VarEmptyDesc")


def _assert_distinguishable(pipeline: dict, *, empty_var: str, absent_var: str) -> None:
    variables = {v["name"]: v for v in pipeline.get("variables", [])}
    empty_decl = variables[empty_var]
    absent_decl = variables[absent_var]
    assert "description" in empty_decl, empty_decl
    assert empty_decl["description"] == "", empty_decl
    assert "description" not in absent_decl, absent_decl


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        resp = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

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


def _pipeline_with_variable_variants(
    name: str,
    role_arn: str,
    bucket: str,
    source_key: str,
    *,
    empty_var: str,
    absent_var: str,
) -> dict:
    empty_var_decl = {"name": empty_var, "defaultValue": "unused", "description": ""}
    absent_var_decl = {"name": absent_var, "defaultValue": "unused"}
    return {
        "name": name,
        "roleArn": role_arn,
        "pipelineType": "V2",
        "artifactStore": {"type": "S3", "location": bucket},
        "variables": [empty_var_decl, absent_var_decl],
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
                "name": "Gate",
                "actions": [
                    {
                        "name": "Approval",
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
