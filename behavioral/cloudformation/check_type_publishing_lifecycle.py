"""type-publishing-lifecycle."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "type-publishing-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterType registers a private MODULE; without publisher status RegisterPublisher, TestType and
    a version-ARN PublishType fail with exact CFNRegistryException messages, else it is tested and
    public; its config is 404 and SetTypeConfiguration '{}' round-trips or is refused for MODULE types."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    register_code, message = _error_code(lambda: cfn.register_publisher(AcceptTermsAndConditions=True))
    if register_code is None:
        publisher = cfn.describe_publisher()
        # DescribePublisher documents every registered publisher as VERIFIED.
        assert publisher["PublisherStatus"] == "VERIFIED", publisher
    else:
        assert register_code == "CFNRegistryException", (
            f"unexpected RegisterPublisher rejection: {register_code}"
        )
        assert message == "You must be a valid AWS Marketplace Seller to be registered as a publisher", (
            f"RegisterPublisher CFNRegistryException message: {message!r}"
        )

    bucket = ctx.unique_name("sim2real-behav-cfnpub-").replace("_", "-")
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    suffix = uuid.uuid4().hex[:10]
    type_name = f"Sim2RealPub{suffix}::Cfn{suffix}::Test::MODULE"
    key = "module.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_module_zip_bytes(type_name))

    token = cfn.register_type(
        Type="MODULE", TypeName=type_name, SchemaHandlerPackage=f"s3://{bucket}/{key}"
    )["RegistrationToken"]
    reg = _poll_until(
        lambda: cfn.describe_type_registration(RegistrationToken=token),
        lambda r: r["ProgressStatus"] != "IN_PROGRESS",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert reg["ProgressStatus"] == "COMPLETE", f"registration failed: {reg}"
    type_arn = reg["TypeArn"]
    version_arn = reg["TypeVersionArn"]
    ctx.on_cleanup(lambda: _safe_deregister(cfn, type_arn))

    if register_code is None:
        test_result = cfn.test_type(Arn=version_arn)
        tested_version_arn = test_result["TypeVersionArn"]
        described = _poll_until(
            lambda: cfn.describe_type(Arn=tested_version_arn),
            lambda d: d.get("TypeTestsStatus") in ("PASSED", "FAILED"),
            timeout_s=180.0,
            interval_s=5.0,
        )
        assert described["TypeTestsStatus"] == "PASSED", (
            f"module failed contract testing: {described.get('TypeTestsStatusDescription')}"
        )
        published = cfn.publish_type(Arn=tested_version_arn)
        public_type_arn = published["PublicTypeArn"]
        assert public_type_arn, "PublishType returned no PublicTypeArn"
        assert type_name.split("::")[-2] in public_type_arn or "MODULE" in public_type_arn
        # Independent read at the public listing, not just PublishType's own response.
        public_types = cfn.list_types(Visibility="PUBLIC", Type="MODULE").get("TypeSummaries", [])
        assert any(t.get("TypeName") == type_name for t in public_types), (
            f"{type_name} must appear in the public registry after a successful PublishType"
        )
    else:
        # The publisher-verification gate that refused RegisterPublisher also refuses
        # TestType, and PublishType refuses a version-qualified ARN (only the default
        # version can be published); assert the specific refusal at each step, then
        # prove -- via independent reads, not just the mutating calls' own responses --
        # that the type never actually got tested or published.
        test_code, message = _error_code(lambda: cfn.test_type(Arn=version_arn))
        assert test_code == "CFNRegistryException", (
            f"unexpected TestType rejection for an unregistered publisher: {test_code}"
        )
        assert message == "You must register as a publisher with CloudFormation to call test-type.", (
            f"TestType CFNRegistryException message: {message!r}"
        )
        described = cfn.describe_type(Arn=version_arn)
        assert described.get("TypeTestsStatus") != "PASSED", (
            f"type must not read as tested when TestType itself was refused: {described}"
        )
        publish_code, message = _error_code(lambda: cfn.publish_type(Arn=version_arn))
        assert publish_code == "CFNRegistryException", (
            f"unexpected PublishType rejection for a version-qualified ARN: {publish_code}"
        )
        assert message == "Only default version can be published. Please remove versionId from Arn", (
            f"PublishType CFNRegistryException message: {message!r}"
        )
        public_types = cfn.list_types(Visibility="PUBLIC", Type="MODULE").get("TypeSummaries", [])
        assert not any(t.get("TypeName") == type_name for t in public_types), (
            f"{type_name} must not appear in the public registry when PublishType was refused"
        )

    # configuration round-trip on the private type: a MODULE with no configuration
    # ever set has no TypeConfiguration to describe -- BatchDescribeTypeConfigurations
    # reports it as a 404 error, not a synthesized empty "{}" entry.
    described_cfg = cfn.batch_describe_type_configurations(
        TypeConfigurationIdentifiers=[{"TypeArn": type_arn}]
    )
    assert not described_cfg["TypeConfigurations"], described_cfg
    assert len(described_cfg["Errors"]) == 1, described_cfg
    assert described_cfg["Errors"][0]["ErrorCode"] == "404", described_cfg["Errors"]

    set_code, message = _error_code(
        lambda: cfn.set_type_configuration(TypeArn=type_arn, Configuration="{}")
    )
    if set_code is None:
        refetched = cfn.batch_describe_type_configurations(
            TypeConfigurationIdentifiers=[{"TypeArn": type_arn}]
        )
        assert json.loads(refetched["TypeConfigurations"][0]["Configuration"]) == {}
    else:
        assert set_code == "CFNRegistryException", (
            f"unexpected error setting configuration on a MODULE type: {set_code}"
        )
        assert message == "TypeConfiguration is not supported for MODULE types", (
            f"SetTypeConfiguration CFNRegistryException message: {message!r}"
        )


def _code(exc) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None


def _error_code(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises, (None, None) on success."""
    try:
        fn()
        return None, None
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _module_zip_bytes(type_name: str) -> bytes:
    # The fragment's top-level keys are validated against the schema's declared
    # "properties" with no implicit allowance -- "AWSTemplateFormatVersion" and
    # "Description" (valid in an ordinary template) are rejected here as extraneous.
    fragment = {
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {},
            }
        },
    }
    # A CloudFormation MODULE package needs both: exactly one JSON/YAML template
    # fragment under a top-level "fragments/" directory, AND a top-level "schema.json"
    # whose "typeName" matches the TypeName passed to RegisterType exactly (real
    # CloudFormation rejects a mismatch with "Type name mismatch. Please check your
    # schema definition"). The schema must describe the fragment's resources through a
    # single required top-level "Resources" property, keyed by the fragment's own
    # logical ids -- real CloudFormation rejects a schema whose "properties" omits it.
    schema = {
        "typeName": type_name,
        "description": "sim2real behavioral test module for publishing",
        "properties": {
            "Resources": {
                "type": "object",
                "properties": {
                    "Topic": {
                        "type": "object",
                        "properties": {"Properties": {"type": "object"}},
                    }
                },
                "additionalProperties": False,
            }
        },
        "additionalProperties": False,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("fragments/module.json", json.dumps(fragment))
        zf.writestr("schema.json", json.dumps(schema))
    return buf.getvalue()


def _safe_deregister(cfn, type_arn: str) -> None:
    """Deregister every non-default version, then the type itself: the default version can only
    go with the type (DeregisterType refuses it by version ARN)."""
    try:
        for v in cfn.list_type_versions(Arn=type_arn)["TypeVersionSummaries"]:
            if v.get("IsDefaultVersion"):
                continue
            try:
                cfn.deregister_type(Arn=v["Arn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "TypeNotFoundException":
                    raise
        cfn.deregister_type(Arn=type_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
