"""type-registration-lifecycle."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-registration-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A registered extension type progresses through registration, version listing,
    activation, default-version selection, deactivation and deregistration consistently
    across describe/list APIs."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    region = ctx.region

    bucket = ctx.unique_name("sim2real-cfntype-").replace("_", "-").lower()
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    suffix = uuid.uuid4().hex[:8]
    type_name = f"Sim2Real{suffix}::Behav{suffix}::Test::MODULE"

    key = "module.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_module_zip_bytes(type_name))
    # RegisterType fetches the SchemaHandlerPackage via the CloudFormation extension
    # registry, which acts under the "resources.cloudformation.amazonaws.com" service
    # principal -- NOT the generic "cloudformation.amazonaws.com" principal used for
    # stack-operation integrations (e.g. SNS notifications). A bucket policy scoped to
    # the generic principal leaves the registry's GetObject fetch as AccessDenied on
    # real AWS, so the async registration deterministically lands in FAILED regardless
    # of retries. A Service-principal grant (rather than Principal "*") also avoids
    # tripping S3 Block Public Access, which is enabled by default on new buckets.
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCloudFormationReadSchemaHandlerPackage",
                        "Effect": "Allow",
                        "Principal": {"Service": "resources.cloudformation.amazonaws.com"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/{key}",
                    }
                ],
            }
        ),
    )

    def _cleanup_type():
        try:
            cfn.deregister_type(Type="MODULE", TypeName=type_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TypeNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_type)

    # MODULE registration's async VALIDATION_STAGE can end FAILED transiently, well
    # before the poll would time out; a bounded retry of the whole register+poll
    # cycle makes this robust without weakening the COMPLETE assertion.
    reg = _register_type_and_wait(cfn, type_name, f"s3://{bucket}/{key}")
    type_version_arn = reg["TypeVersionArn"]
    version_id = type_version_arn.rsplit("/", 1)[-1]

    tokens = cfn.list_type_registrations(
        Type="MODULE", TypeName=type_name, RegistrationStatusFilter="COMPLETE"
    )["RegistrationTokenList"]
    assert reg["RegistrationToken"] in tokens, tokens

    described = cfn.describe_type(Type="MODULE", TypeName=type_name)
    assert described["DeprecatedStatus"] == "LIVE", described
    assert described["DefaultVersionId"] == version_id, described

    versions = cfn.list_type_versions(Type="MODULE", TypeName=type_name)["TypeVersionSummaries"]
    assert any(v["VersionId"] == version_id for v in versions), versions

    cfn.set_type_default_version(Type="MODULE", TypeName=type_name, VersionId=version_id)
    reconfirmed = cfn.describe_type(Type="MODULE", TypeName=type_name)
    assert reconfirmed["DefaultVersionId"] == version_id

    types_page = cfn.list_types(Visibility="PRIVATE", Type="MODULE", MaxResults=100)
    assert "TypeSummaries" in types_page

    cfn.deregister_type(Type="MODULE", TypeName=type_name)

    final_error = _wait_type_not_found(cfn, type_name, timeout_s=60, interval_s=3)
    expected = ("TypeNotFoundException", f"The type '{type_name}' cannot be found.")
    assert final_error == expected, f"expected {expected!r} after DeregisterType, got {final_error!r}"


def _module_zip_bytes(type_name: str) -> bytes:
    # A MODULE package needs the template fragment under a top-level "fragments/"
    # directory named "fragment.json" (not an arbitrary filename), plus a
    # top-level "schema.json" describing the module's properties. Real AWS
    # RegisterType's async VALIDATION_STAGE deterministically FAILS with
    # "One or more of the following files are missing from the input artifact:
    # [schema.json, fragment.json]" when either is absent or misnamed.
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


def _wait_type_not_found(cfn, type_name, *, timeout_s=60.0, interval_s=3.0):
    """Poll DescribeType until it rejects the deregistered MODULE; return the rejection's
    (Error.Code, Error.Message). Raises when the type still resolves at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfn.describe_type(Type="MODULE", TypeName=type_name)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"type {type_name} still resolves via DescribeType after {timeout_s}s")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _register_type_and_wait(cfn, type_name, schema_handler_package, *, max_attempts=3, timeout_s=180.0, interval_s=5.0):
    last_reg = None
    for _ in range(max_attempts):
        reg_token = cfn.register_type(
            Type="MODULE", TypeName=type_name, SchemaHandlerPackage=schema_handler_package
        )["RegistrationToken"]
        reg = _poll_until(
            lambda: cfn.describe_type_registration(RegistrationToken=reg_token),
            lambda r: r["ProgressStatus"] in ("COMPLETE", "FAILED"),
            timeout_s=timeout_s,
            interval_s=interval_s,
        )
        if reg["ProgressStatus"] == "COMPLETE":
            reg = dict(reg)
            reg["RegistrationToken"] = reg_token
            return reg
        last_reg = reg
    raise AssertionError(
        f"type registration for {type_name} did not COMPLETE after {max_attempts} attempts; "
        f"last description={last_reg.get('Description') if last_reg else None}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
