"""pipeline-artifact-store-encryption-key-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipeline-artifact-store-encryption-key-preserved"
GROUP = "server-side"
SERVICES = ["codepipeline"]
_SCENARIO = "codepipeline-artifact-store-encryption-key-preserved"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An EncryptionKey (KMS key ARN and type) set on the pipeline's ArtifactStore at
    CreatePipeline is returned byte-identical by GetPipeline, with no default
    AWS-managed-key substitution."""
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-cp-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": _SCENARIO}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    role_arn = _create_pipeline_role(ctx)
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key="src.txt", Body=b"x")

    name = ctx.unique_name("sim2real-cp-pipe-")
    cp = ctx.client("codepipeline")
    _create_pipeline_with_retry(
        cp,
        {
            "name": name,
            "roleArn": role_arn,
            "artifactStore": {
                "type": "S3",
                "location": bucket,
                "encryptionKey": {"id": key_arn, "type": "KMS"},
            },
            "stages": _minimal_stages(bucket, "src.txt"),
        },
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    fetched = cp.get_pipeline(name=name)["pipeline"]
    enc = fetched["artifactStore"]["encryptionKey"]
    assert enc["id"] == key_arn, f"expected encryptionKey.id {key_arn!r}, got {enc['id']!r}"
    assert enc["type"] == "KMS", f"expected encryptionKey.type 'KMS', got {enc['type']!r}"


def _create_pipeline_with_retry(
    cp, pipeline: dict, attempts: int = 6, delay_s: float = 5.0, tags: list | None = None
) -> dict:
    """CreatePipeline can transiently fail with InvalidStructureException /
    ValidationException while the just-created IAM role's trust policy propagates."""
    from botocore.exceptions import ClientError

    kwargs: dict[str, Any] = {"pipeline": pipeline}
    if tags is not None:
        kwargs["tags"] = tags
    last_err = None
    for _ in range(attempts):
        try:
            return cp.create_pipeline(**kwargs)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _create_pipeline_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cp-policy-")
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_bucket(ctx, versioning: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-").lower()
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    if versioning:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
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


def _minimal_stages(source_bucket, source_key, approval_action_name="Approve", approval_config=None):
    return [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                    "configuration": {
                        "S3Bucket": source_bucket,
                        "S3ObjectKey": source_key,
                        "PollForSourceChanges": "false",
                    },
                    "outputArtifacts": [{"name": "SourceArtifact"}],
                }
            ],
        },
        {
            "name": "Approval",
            "actions": [
                {
                    "name": approval_action_name,
                    "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                    "configuration": approval_config or {},
                }
            ],
        },
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
