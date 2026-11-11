"""deregister-aws-owned-type-rejected."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-aws-owned-type-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterType and SetTypeDefaultVersion are refused for an AWS-owned type (AWS::SNS::Topic),
    which stays untouched; both calls first succeed on a private MODULE as a positive control."""
    cfn = ctx.client("cloudformation")

    control_type_name, control_version_id = _register_private_module(ctx, cfn)
    cfn.set_type_default_version(Type="MODULE", TypeName=control_type_name, VersionId=control_version_id)
    cfn.deregister_type(Type="MODULE", TypeName=control_type_name)
    control_gone = _expect_error(lambda: cfn.describe_type(Type="MODULE", TypeName=control_type_name))
    control_expected = ("TypeNotFoundException", f"The type '{control_type_name}' cannot be found.")
    assert control_gone == control_expected, (
        f"positive control: the deregistered private module: expected {control_expected!r}, "
        f"got {control_gone!r}"
    )

    aws_owned_type_name = "AWS::SNS::Topic"

    described = cfn.describe_type(Type="RESOURCE", TypeName=aws_owned_type_name)
    assert described["TypeName"] == aws_owned_type_name
    assert described.get("Arn"), "expected an Arn for a well-known AWS-owned type"

    deregister_got = _expect_error(
        lambda: cfn.deregister_type(Type="RESOURCE", TypeName=aws_owned_type_name)
    )
    # Real CloudFormation has no registry entry for an AWS-owned native type under
    # the caller's account, so DeregisterType reports it as simply not found rather
    # than raising a generic registry-policy exception.
    deregister_expected = ("TypeNotFoundException", f"The type '{aws_owned_type_name}' cannot be found.")
    assert deregister_got == deregister_expected, (
        f"deregistering an AWS-owned type: expected {deregister_expected!r}, got {deregister_got!r}"
    )

    set_default_got = _expect_error(
        lambda: cfn.set_type_default_version(
            Type="RESOURCE", TypeName=aws_owned_type_name, VersionId="00000001"
        )
    )
    set_default_expected = ("TypeNotFoundException", f"The type '{aws_owned_type_name}' cannot be found.")
    assert set_default_got == set_default_expected, (
        f"setting a default version on an AWS-owned type: expected {set_default_expected!r}, "
        f"got {set_default_got!r}"
    )

    # The type must remain completely untouched.
    still_there = cfn.describe_type(Type="RESOURCE", TypeName=aws_owned_type_name)
    assert still_there["TypeName"] == aws_owned_type_name
    assert still_there["Arn"] == described["Arn"]




def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) if it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _module_zip_bytes(type_name: str) -> bytes:
    fragment = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "sim2real positive-control module",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    schema = {
        "typeName": type_name,
        "description": "sim2real positive-control module",
        "properties": {"Resources": {"type": "object"}},
        "additionalProperties": True,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("fragments/fragment.json", json.dumps(fragment))
        zf.writestr("schema.json", json.dumps(schema))
    return buf.getvalue()


def _delete_bucket(s3, bucket) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _safe_deregister(cfn, type_name) -> None:
    try:
        cfn.deregister_type(Type="MODULE", TypeName=type_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


def _register_private_module(ctx, cfn):
    """Register a throwaway private MODULE (S3 upload, RegisterType, poll to terminal status).
    Returns (type_name, version_id)."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfnownedctl-").lower().replace("_", "-")
    # S3 CreateBucket rejects an explicit LocationConstraint of "us-east-1" -- it's the
    # one region where the constraint must be omitted entirely. The bucket still lands
    # in ctx.region either way; this is an S3 API quirk, not a pinned region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    type_name = f"Sim2realBehav::OwnedCtl::{uuid.uuid4().hex[:12]}::MODULE"
    key = f"module-{uuid.uuid4().hex}.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_module_zip_bytes(type_name))

    token = cfn.register_type(
        Type="MODULE", TypeName=type_name, SchemaHandlerPackage=f"s3://{bucket}/{key}"
    )["RegistrationToken"]
    ctx.on_cleanup(lambda: _safe_deregister(cfn, type_name))
    reg = _poll_until(
        lambda: cfn.describe_type_registration(RegistrationToken=token),
        lambda r: r["ProgressStatus"] in ("COMPLETE", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert reg["ProgressStatus"] == "COMPLETE", (
        f"positive-control MODULE registration did not COMPLETE: {reg.get('Description')}"
    )
    version_id = reg["TypeVersionArn"].rsplit("/", 1)[-1]
    return type_name, version_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
