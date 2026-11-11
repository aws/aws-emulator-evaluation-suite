"""deregister-in-use-type-version-rejected."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-in-use-type-version-rejected"
GROUP = 'errors'
SERVICES = ['cloudformation']


def _expect_error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

def _module_fragment_zip_bytes(description, type_name):
    """A minimal, valid MODULE package (fragment + schema) RegisterType expects."""
    fragment = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": description,
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    schema = {
        "typeName": type_name,
        "description": description,
        "properties": {"Resources": {"type": "object"}},
        "additionalProperties": True,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("fragments/fragment.json", json.dumps(fragment))
        zf.writestr("schema.json", json.dumps(schema))
    return buf.getvalue()

def _register_module_version(ctx, cf, type_name, description):
    """Upload a module zip to a new bucket, RegisterType, poll to COMPLETE; return the version id."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cfn-modpkg-").lower()
    if ctx.region == "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint of "us-east-1".
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    key = f"module-{uuid.uuid4().hex}.zip"

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_object(Bucket=bucket, Key=key, Body=_module_fragment_zip_bytes(description, type_name))
    s3_uri = f"s3://{bucket}/{key}"

    token = cf.register_type(
        Type="MODULE", TypeName=type_name, SchemaHandlerPackage=s3_uri
    )["RegistrationToken"]
    deadline = time.monotonic() + 180
    result = cf.describe_type_registration(RegistrationToken=token)
    while time.monotonic() < deadline:
        result = cf.describe_type_registration(RegistrationToken=token)
        if result.get("ProgressStatus") in {"COMPLETE", "FAILED"}:
            break
        time.sleep(3)
    assert result.get("ProgressStatus") == "COMPLETE", result.get("Description")
    return result["TypeVersionArn"].rsplit("/", 1)[-1]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterType on a MODULE's default version is a CFNRegistryException, with or without another
    active version, while the non-default version deregisters; deregistering the whole type
    succeeds and DescribeType then reports TypeNotFoundException."""
    cf = ctx.client("cloudformation")
    token = ctx.unique_name("")[:20]
    type_name = f"Sim2realBehav::Probe::{token}::MODULE"
    ctx.on_cleanup(lambda: cf.deregister_type(Type="MODULE", TypeName=type_name))

    v1 = _register_module_version(ctx, cf, type_name, "sim2real-behav module v1")
    v2 = _register_module_version(ctx, cf, type_name, "sim2real-behav module v2")

    versions = cf.list_type_versions(Type="MODULE", TypeName=type_name)["TypeVersionSummaries"]
    ids = {v["VersionId"] for v in versions}
    assert ids == {v1, v2}, ids

    default_versions = [v for v in versions if v.get("IsDefaultVersion")]
    assert len(default_versions) == 1, versions
    default_id = default_versions[0]["VersionId"]
    other_id = next(v["VersionId"] for v in versions if v["VersionId"] != default_id)

    got = _expect_error(
        lambda: cf.deregister_type(Type="MODULE", TypeName=type_name, VersionId=default_id)
    )
    expected = (
        "CFNRegistryException",
        f"Version '{default_id}' is the default version and cannot be deregistered. "
        f"Deregister the resource type '{type_name}' instead.",
    )
    assert got == expected, f"deregistering the default version: expected {expected!r}, got {got!r}"

    still_versions = cf.list_type_versions(Type="MODULE", TypeName=type_name)["TypeVersionSummaries"]
    still_ids = {v["VersionId"] for v in still_versions}
    assert still_ids == {v1, v2}, f"expected both versions {{v1, v2}} still registered, found {still_ids}"

    cf.deregister_type(Type="MODULE", TypeName=type_name, VersionId=other_id)

    # Even as the sole remaining version, the default is only removable via the whole type.
    got = _expect_error(
        lambda: cf.deregister_type(Type="MODULE", TypeName=type_name, VersionId=default_id)
    )
    expected = (
        "CFNRegistryException",
        f"Version '{default_id}' is the default version and cannot be deregistered. "
        f"Deregister the resource type '{type_name}' instead.",
    )
    assert got == expected, f"deregistering the last version by id: expected {expected!r}, got {got!r}"
    cf.deregister_type(Type="MODULE", TypeName=type_name)

    # DescribeType can keep returning the type briefly after DeregisterType.
    deadline = time.monotonic() + 90
    while True:
        try:
            cf.describe_type(Type="MODULE", TypeName=type_name)
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"type {type_name} is still describable 90s after DeregisterType")
        time.sleep(3)
    expected = ("TypeNotFoundException", f"The type '{type_name}' cannot be found.")
    assert got == expected, f"describing the deregistered type: expected {expected!r}, got {got!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
