"""deregister-inuse-type-rejected."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-inuse-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterType on a MODULE's default version is rejected with CFNRegistryException while another
    version is active, leaving both registered; the non-default version deregisters normally."""
    cfn = ctx.client("cloudformation")
    bucket = _create_scratch_bucket(ctx)
    type_name = _module_type_name(ctx)

    # Sequential: concurrent RegisterType calls for the same TypeName can contend and never
    # reach COMPLETE.
    v1_id, v1_arn = _register_module_version(ctx, bucket, type_name, "v1")
    v2_id, v2_arn = _register_module_version(ctx, bucket, type_name, "v2")
    ctx.on_cleanup(lambda: _cleanup_module_type(cfn, type_name, [v1_id, v2_id]))

    described = cfn.describe_type(Type="MODULE", TypeName=type_name)
    default_version_id = described["DefaultVersionId"]
    # The latest registration normally becomes the default; force it if not.
    if default_version_id != v2_id:
        cfn.set_type_default_version(Type="MODULE", TypeName=type_name, VersionId=v2_id)
        default_version_id = v2_id
    other_version_id = v1_id if default_version_id == v2_id else v2_id

    got = _expect_error(lambda: cfn.deregister_type(
        Type="MODULE", TypeName=type_name, VersionId=default_version_id,
    ))
    expected = (
        "CFNRegistryException",
        f"Version '{default_version_id}' is the default version and cannot be deregistered. "
        f"Deregister the resource type '{type_name}' instead.",
    )
    assert got == expected, f"expected {expected!r}, got {got!r}"

    still_there = cfn.list_type_versions(Type="MODULE", TypeName=type_name)["TypeVersionSummaries"]
    assert len(still_there) == 2, f"expected both module versions to remain registered, found {still_there}"

    cfn.deregister_type(Type="MODULE", TypeName=type_name, VersionId=other_version_id)
    remaining = cfn.list_type_versions(Type="MODULE", TypeName=type_name)["TypeVersionSummaries"]
    remaining_ids = {v["VersionId"] for v in remaining}
    assert remaining_ids == {default_version_id}, (
        f"expected only the default version {default_version_id} to remain after deregistering "
        f"the non-default version, found {remaining_ids}"
    )


def _expect_error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _alnum(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", value)


def _module_type_name(ctx) -> str:
    suffix = _alnum(ctx.unique_name("Mod"))[:40]
    return f"Sim2real::Behav::{suffix}::MODULE"


def _create_scratch_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-mod-src-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    # A MODULE package is fetched by cloudformation.amazonaws.com, a RESOURCE package by
    # resources.cloudformation.amazonaws.com; granting only the latter fails every MODULE
    # registration, so grant both.
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCloudFormationRegisterTypeRead",
                    "Effect": "Allow",
                    "Principal": {"Service": "resources.cloudformation.amazonaws.com"},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                },
                {
                    "Sid": "AllowCloudFormationRegisterTypeBucketLocation",
                    "Effect": "Allow",
                    "Principal": {"Service": "resources.cloudformation.amazonaws.com"},
                    "Action": "s3:GetBucketLocation",
                    "Resource": f"arn:aws:s3:::{bucket}",
                },
                {
                    "Sid": "AllowCloudFormationCoreRegisterTypeRead",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudformation.amazonaws.com"},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                },
                {
                    "Sid": "AllowCloudFormationCoreRegisterTypeBucketLocation",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudformation.amazonaws.com"},
                    "Action": "s3:GetBucketLocation",
                    "Resource": f"arn:aws:s3:::{bucket}",
                },
            ],
        }),
    )
    # Bucket-policy propagation can lag the registry fetch by tens of seconds; the register
    # retry loop absorbs it instead of a fixed sleep.
    return bucket


def _build_module_zip(type_name: str) -> bytes:
    # A MODULE package holds one fragment under "fragments/" plus "schema.json". The fragment's
    # top-level keys are validated against the schema's properties, so a strict schema
    # ("additionalProperties": false) is rejected as "extraneous key"; use a permissive one.
    fragment = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "sim2real behavioral test module",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    schema = {
        "typeName": type_name,
        "description": "sim2real behavioral test module",
        "properties": {"Resources": {"type": "object"}},
        "additionalProperties": True,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("fragments/fragment.json", json.dumps(fragment))
        zf.writestr("schema.json", json.dumps(schema))
    return buf.getvalue()


def _register_module_version(ctx, bucket, type_name, label, attempts=8, retry_wait_s=20.0,
                              poll_timeout_s=180):
    """RegisterType with a fresh upload and poll; retry on FAILED (bucket-policy propagation lag)
    on the same TypeName, a bounded number of times. Returns (version_id, type_version_arn)."""
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    last_reg = None
    for attempt in range(1, attempts + 1):
        key = ctx.unique_name(f"sim2real-behav-mod-{label}-") + ".zip"
        s3.put_object(Bucket=bucket, Key=key, Body=_build_module_zip(type_name))
        ctx.on_cleanup(lambda key=key: _safe(lambda: s3.delete_object(Bucket=bucket, Key=key)))

        resp = cfn.register_type(
            Type="MODULE", TypeName=type_name, SchemaHandlerPackage=f"s3://{bucket}/{key}",
        )
        token = resp["RegistrationToken"]
        deadline = time.monotonic() + poll_timeout_s
        status = None
        reg = None
        while time.monotonic() < deadline:
            reg = cfn.describe_type_registration(RegistrationToken=token)
            status = reg["ProgressStatus"]
            if status in ("COMPLETE", "FAILED"):
                break
            time.sleep(5)
        if status == "COMPLETE":
            type_version_arn = reg["TypeVersionArn"]
            version_id = type_version_arn.rsplit("/", 1)[-1]
            return version_id, type_version_arn
        last_reg = reg
        if status != "FAILED":
            raise AssertionError(
                f"module registration {label} never reached a terminal ProgressStatus within "
                f"{poll_timeout_s}s (last={reg})"
            )
        if attempt < attempts:
            time.sleep(retry_wait_s)
    raise AssertionError(f"module registration {label} did not complete after {attempts} attempts: {last_reg}")


def _cleanup_module_type(cfn, type_name, version_ids):
    for version_id in version_ids:
        try:
            cfn.deregister_type(Type="MODULE", TypeName=type_name, VersionId=version_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TypeNotFoundException":
                raise
    try:
        cfn.deregister_type(Type="MODULE", TypeName=type_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
