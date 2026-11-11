"""pipeline-structure-unicode-names-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipeline-structure-unicode-names-round-trip"
GROUP = "server-side"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A unicode/emoji pipeline name is rejected with ValidationException (names are ASCII-only),
    while a unicode/emoji action configuration value (approval CustomData) round-trips
    byte-identical through GetPipeline."""
    cp = ctx.client("codepipeline")
    role_arn = _create_pipeline_role(ctx)
    bucket = _create_bucket(ctx, versioning=True)
    ctx.client("s3").put_object(Bucket=bucket, Key="src.txt", Body=b"x")

    unicode_name = "pipeline-\u65e5\u672c-\U0001f680"
    error = _rejected(
        ctx,
        lambda: cp.create_pipeline(
            pipeline={
                "name": unicode_name,
                "roleArn": role_arn,
                "artifactStore": {"type": "S3", "location": bucket},
                "stages": _minimal_stages(bucket, "src.txt"),
            }
        ),
        cleanup_name=unicode_name,
    )
    assert error["Code"] == "ValidationException", (
        f"a unicode/emoji pipeline name should be rejected with ValidationException, got "
        f"{error['Code']!r} ({error.get('Message')!r})"
    )
    expected_message = (
        "1 validation error detected: Value at 'pipeline.name' failed to satisfy constraint: "
        r"Member must satisfy regular expression pattern: [A-Za-z0-9.@\-_]+"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    unicode_value = "\u65e5\u672c\u8a9e \U0001f680 caf\u00e9"
    name = ctx.unique_name("sim2real-cp-pipe-")
    _create_pipeline_with_retry(
        cp,
        {
            "name": name,
            "roleArn": role_arn,
            "artifactStore": {"type": "S3", "location": bucket},
            "stages": _minimal_stages(bucket, "src.txt", approval_config={"CustomData": unicode_value}),
        },
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    fetched = cp.get_pipeline(name=name)["pipeline"]
    approval_action = fetched["stages"][1]["actions"][0]
    actual = approval_action["configuration"]["CustomData"]
    assert actual == unicode_value, (
        f"CustomData round-tripped via GetPipeline as {actual!r}, expected byte-identical "
        f"{unicode_value!r}"
    )


def _rejected(ctx, fn, cleanup_name):
    """Call fn() and return its botocore Error dict; an unexpected success raises, after
    registering the created pipeline for cleanup so it cannot leak."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    ctx.on_cleanup(lambda: ctx.client("codepipeline").delete_pipeline(name=cleanup_name))
    raise AssertionError(
        f"real AWS rejects a unicode/emoji pipeline name, but CreatePipeline SUCCEEDED and "
        f"returned {result!r}"
    )


def _create_pipeline_with_retry(cp, pipeline: dict, attempts: int = 6, delay_s: float = 5.0) -> dict:
    """CreatePipeline can transiently fail with InvalidStructureException /
    ValidationException while the just-created IAM role's trust policy propagates."""
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            return cp.create_pipeline(pipeline=pipeline)
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
