"""pipeline-name-unicode-round-trip."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-name-unicode-round-trip"
GROUP = "representation"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pipeline created using the full allowed name character set plus a tag
    value containing unicode text round-trips byte-identical through GetPipeline
    and ListTagsForResource."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _upload_source_zip(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)

    # Pipeline names are constrained to [A-Za-z0-9.@\-_]+ -- exercise the full
    # allowed charset rather than plain alphanumerics.
    name = ctx.unique_name("sim2real.cp@unicode-name_")
    # AWS resource tag values are restricted server-side to letters (any unicode
    # script), numbers, spaces, and a fixed punctuation set (_.:/=+-@) -- symbols
    # like emoji are rejected with InvalidTagsException, so exercise the allowed
    # unicode letter ranges (Latin-accented, CJK, Greek) rather than emoji.
    unicode_tag_value = "h\u00e9llo-\u4e16\u754c-\u03a9-caf\u00e9"

    pipeline_def = _two_stage_pipeline(name, role_arn, bucket, key)
    _wait_role_usable(
        lambda: cp.create_pipeline(
            pipeline=pipeline_def,
            tags=[{"key": "sim2real-unicode-tag", "value": unicode_tag_value}],
        )
    )
    _register_pipeline_cleanup(ctx, cp, name)

    fetched = cp.get_pipeline(name=name)
    assert fetched["pipeline"]["name"] == name, (
        f"pipeline name mangled on round trip: expected {name!r}, "
        f"got {fetched['pipeline']['name']!r}"
    )

    pipeline_arn = fetched["metadata"]["pipelineArn"]
    tags = cp.list_tags_for_resource(resourceArn=pipeline_arn)["tags"]
    tag_map = {t["key"]: t["value"] for t in tags}
    assert tag_map["sim2real-unicode-tag"] == unicode_tag_value, (
        f"unicode tag value mangled on round trip: expected {unicode_tag_value!r}, "
        f"got {tag_map.get('sim2real-unicode-tag')!r}"
    )

    cp.delete_pipeline(name=name)
    error = _error(lambda: cp.get_pipeline(name=name))
    assert error.get("Code") == "PipelineNotFoundException", (
        f"expected PipelineNotFoundException reading a deleted pipeline, got {error!r}"
    )
    expected_message = f"Account '{ctx.account}' does not have a pipeline with name '{name}'"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


# ===== helpers =====


def _register_pipeline_cleanup(ctx, cp, name: str) -> None:
    def _cleanup() -> None:
        try:
            cp.delete_pipeline(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PipelineNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]
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
