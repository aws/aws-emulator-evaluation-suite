"""type-configuration-roundtrip."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-configuration-roundtrip"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetTypeConfiguration on a registered MODULE type fails with CFNRegistryException and no
    configuration exists for it, while an unknown TypeName fails with TypeNotFoundException.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    region = ctx.region

    bucket = ctx.unique_name("sim2real-cfncfg-").replace("_", "-").lower()
    # S3 CreateBucket rejects an explicit LocationConstraint of "us-east-1".
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    suffix = uuid.uuid4().hex[:8]
    type_name = f"Sim2Real{suffix}::Cfg{suffix}::Test::MODULE"
    ctx.on_cleanup(lambda: _safe_deregister(cfn, type_name))

    key = "module.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_module_zip_bytes(type_name))
    # The registry fetches the package as resources.cloudformation.amazonaws.com, not the generic
    # cloudformation principal; a Service grant also avoids tripping Block Public Access.
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

    # MODULE validation occasionally lands in FAILED transiently, so registration is retried.
    reg = _register_type_and_wait(cfn, type_name, f"s3://{bucket}/{key}")
    type_arn = reg["TypeArn"]
    # Positive control: an independent DescribeType read confirms the registration.
    described = cfn.describe_type(Arn=type_arn)
    assert described["Type"] == "MODULE", described
    assert described["TypeName"] == type_name, described

    configuration = json.dumps({"Parameters": {"apiKey": "sim2real-secret-value"}})
    code, message = _error_code_and_message(
        lambda: cfn.set_type_configuration(
            TypeArn=type_arn, Configuration=configuration, ConfigurationAlias="default"
        )
    )
    assert (code, message) == (
        "CFNRegistryException",
        "TypeConfiguration is not supported for MODULE types",
    ), (code, message)

    # Discriminator: an unknown TypeName fails differently, so the MODULE rejection is about category.
    never_registered = f"Sim2Real{uuid.uuid4().hex[:8]}::Missing::Test"
    missing_code, missing_message = _error_code_and_message(
        lambda: cfn.set_type_configuration(
            TypeName=never_registered, Type="RESOURCE", Configuration="{}", ConfigurationAlias="default"
        )
    )
    assert missing_code != code, (missing_code, code, missing_message)
    assert (missing_code, missing_message) == (
        "TypeNotFoundException",
        f"The type '{never_registered}' cannot be found.",
    ), (missing_code, missing_message)

    # Effect absent: the independent read agrees no configuration exists for the MODULE.
    batch = cfn.batch_describe_type_configurations(
        TypeConfigurationIdentifiers=[{"TypeArn": type_arn, "TypeConfigurationAlias": "default"}]
    )
    assert not batch["TypeConfigurations"], batch["TypeConfigurations"]
    failures = batch.get("Errors", []) + batch.get("UnprocessedTypeConfigurations", [])
    assert len(failures) == 1, f"expected the MODULE's absent configuration to surface as exactly one failure, got: {batch}"
    assert (failures[0].get("ErrorCode"), failures[0].get("ErrorMessage")) == (
        "404",
        "TypeConfiguration not found",
    ), f"expected the absent configuration to report 404 'TypeConfiguration not found', got: {batch}"


def _error_code_and_message(fn):
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call succeeded with: {resp}")


def _module_zip_bytes(type_name: str) -> bytes:
    # schema.json "typeName" must equal the RegisterType TypeName; a module fragment may not
    # contain "AWSTemplateFormatVersion".
    fragment = b'{"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}'
    schema = json.dumps(
        {
            "typeName": type_name,
            "description": "Sim2Real behavioral test module.",
            "properties": {"Resources": {"type": "object"}},
            "additionalProperties": False,
        }
    ).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("schema.json", schema)
        zf.writestr("fragments/fragment.json", fragment)
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
