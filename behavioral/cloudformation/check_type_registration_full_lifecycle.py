"""type-registration-full-lifecycle."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-registration-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A registered RESOURCE type is listed, FULLY_MUTABLE and versioned; a second version leaves
    the default until SetTypeDefaultVersion moves it; whole-type DeregisterType is refused while
    two versions are active, and succeeds after the non-default one is deregistered."""
    cfn = ctx.client("cloudformation")
    bucket = _create_bucket(ctx)
    type_name = _unique_type_name(ctx)

    schema_v1 = _minimal_schema(type_name, extra_property=False)
    reg1 = _register_resource_type(ctx, bucket, type_name, schema_v1, "v1")
    type_arn = reg1["TypeArn"]
    version_arn_1 = reg1["TypeVersionArn"]
    version_id_1 = version_arn_1.rsplit("/", 1)[-1]

    # RegistrationStatusFilter defaults to IN_PROGRESS, so a completed registration is invisible
    # without asking for COMPLETE.
    listed_tokens = cfn.list_type_registrations(
        TypeName=type_name, Type="RESOURCE", RegistrationStatusFilter="COMPLETE"
    )["RegistrationTokenList"]
    assert reg1["RegistrationToken"] in listed_tokens, (
        f"expected our registration token {reg1['RegistrationToken']!r} listed, got {listed_tokens}"
    )

    # A RESOURCE registered with all five handlers declared is FULLY_MUTABLE.
    described = cfn.describe_type(Arn=type_arn)
    assert described["TypeName"] == type_name, described
    assert described["ProvisioningType"] == "FULLY_MUTABLE", described
    assert described["DeprecatedStatus"] == "LIVE", described
    assert described["DefaultVersionId"] == version_id_1, described

    schema_v2 = _minimal_schema(type_name, extra_property=True)
    reg2 = _register_resource_type(ctx, bucket, type_name, schema_v2, "v2")
    version_arn_2 = reg2["TypeVersionArn"]
    version_id_2 = version_arn_2.rsplit("/", 1)[-1]
    assert version_id_2 != version_id_1, (
        f"second registration reused version id {version_id_1}"
    )

    versions = cfn.list_type_versions(Arn=type_arn)["TypeVersionSummaries"]
    version_ids = {v["VersionId"] for v in versions}
    assert version_id_1 in version_ids and version_id_2 in version_ids, (
        f"expected both {version_id_1!r} and {version_id_2!r} in {version_ids}"
    )

    # Registering a second version keeps the first as default; only SetTypeDefaultVersion moves it.
    described_after_v2 = cfn.describe_type(Arn=type_arn)
    assert described_after_v2["DefaultVersionId"] == version_id_1, (
        f"expected the default to stay at the first registered version {version_id_1!r} after "
        f"registering {version_id_2!r}, got {described_after_v2['DefaultVersionId']!r}"
    )

    # SetTypeDefaultVersion returns before DescribeType reflects the new default, so poll.
    cfn.set_type_default_version(Arn=version_arn_2)
    observed_default = _poll_until(
        lambda: cfn.describe_type(Arn=type_arn)["DefaultVersionId"],
        lambda v: v == version_id_2,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert observed_default == version_id_2, (
        f"expected SetTypeDefaultVersion to move the default to {version_id_2!r}, got "
        f"{observed_default!r}"
    )

    # A type with more than one active version cannot be deregistered as a whole.
    premature = _error_code_and_message(lambda: cfn.deregister_type(Arn=type_arn))
    expected_premature = (
        "CFNRegistryException",
        "This type has more than one active version. Please deregister non-default active "
        "versions before attempting to deregister the type.",
    )
    assert premature == expected_premature, (
        f"expected DeregisterType on a type with two active versions to be rejected with "
        f"{expected_premature!r}, got {premature!r}"
    )

    assert cfn.describe_type(Arn=type_arn)["TypeName"] == type_name, (
        "the refused DeregisterType must not have removed the type"
    )

    cfn.deregister_type(Arn=version_arn_1)
    cfn.deregister_type(Arn=type_arn)
    # DeregisterType returns before the name stops resolving, so poll. Keyed on Type+TypeName:
    # a deregistered version Arn keeps resolving.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            cfn.describe_type(Type="RESOURCE", TypeName=type_name)
        except ClientError as exc:
            final = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
            if final[0] == "TypeNotFoundException" or time.monotonic() >= deadline:
                break
        else:
            assert time.monotonic() < deadline, f"type {type_name!r} still resolves 120 s after DeregisterType"
        time.sleep(2)
    expected_final = ("TypeNotFoundException", f"The type '{type_name}' cannot be found.")
    assert final == expected_final, (
        f"expected {expected_final!r} after DeregisterType, got {final!r}"
    )




def _error_code_and_message(fn):
    """Single-shot refusal probe: raises if the call unexpectedly succeeds, so an over-permissive
    target reads as a failed refusal rather than a silent code mismatch."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() > deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s; last result={result}"
            )
        time.sleep(interval_s)
        result = probe()
    return result


def _unique_type_name(ctx) -> str:
    suffix = ctx.unique_name("x").replace("-", "").replace("_", "")
    suffix = "".join(c for c in suffix if c.isalnum())[:20] or "abc123"
    return f"Sim2real{suffix}::Behav::Widget"


def _minimal_schema(type_name: str, extra_property: bool) -> dict:
    properties = {
        "Id": {"description": "Identifier", "type": "string"},
        "Name": {"description": "Name", "type": "string"},
    }
    if extra_property:
        properties["Extra"] = {"description": "Extra optional field", "type": "string"}
    return {
        "typeName": type_name,
        "description": "Simparity behavioral fidelity test resource provider.",
        "properties": properties,
        "primaryIdentifier": ["/properties/Id"],
        "readOnlyProperties": ["/properties/Id"],
        "createOnlyProperties": ["/properties/Name"],
        "additionalProperties": False,
        # A RESOURCE schema must declare its handlers; without them the registry's
        # VALIDATION_STAGE rejects the package.
        "handlers": {
            name: {"permissions": []}
            for name in ("create", "read", "update", "delete", "list")
        },
    }


def _resource_package_bytes(type_name: str, schema: dict) -> bytes:
    """The schema.json + .rpdk-config + lambda package zip a RESOURCE type requires; without the
    last two, registration fails VALIDATION_STAGE. The handler is never invoked, so it is a stub.
    """
    handler_src = (
        "def handler(event, context):\n"
        "    return {\n"
        "        'status': 'FAILED',\n"
        "        'errorCode': 'GeneralServiceException',\n"
        "        'message': 'sim2real behavioral fidelity stub provider',\n"
        "    }\n"
    )
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("handler.py", handler_src)
    rpdk_config = {
        "artifact_type": "RESOURCE",
        "typeName": type_name,
        "language": "python311",
        "runtime": "python3.11",
        "entrypoint": "handler.handler",
        "testEntrypoint": "handler.handler",
        "settings": {"version": False, "subparser_name": None, "protocolVersion": "2.0.0"},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("schema.json", json.dumps(schema))
        zf.writestr(".rpdk-config", json.dumps(rpdk_config))
        zf.writestr("ResourceProvider.zip", inner.getvalue())
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfnreg-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    # The registry fetches the package as "resources.cloudformation.amazonaws.com", not the
    # stack principal; without this grant registration fails. GetBucketLocation on the bucket
    # lets it resolve the region, and a service-principal grant passes Block Public Access.
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
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    },
                    {
                        "Sid": "AllowCloudFormationResolveBucketLocation",
                        "Effect": "Allow",
                        "Principal": {"Service": "resources.cloudformation.amazonaws.com"},
                        "Action": "s3:GetBucketLocation",
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                ],
            }
        ),
    )
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _register_resource_type(
    ctx, bucket: str, type_name: str, schema: dict, version_tag: str
) -> dict:
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    # The registry validates the package by file name: "schema.json", ".rpdk-config" and a
    # lambda deployment package must all be present.
    key = f"packages/{type_name.replace('::', '-')}-{version_tag}.zip"
    s3.put_object(
        Bucket=bucket, Key=key, Body=_resource_package_bytes(type_name, schema)
    )

    resp = cfn.register_type(
        Type="RESOURCE", TypeName=type_name, SchemaHandlerPackage=f"s3://{bucket}/{key}"
    )
    token = resp["RegistrationToken"]
    ctx.on_cleanup(lambda: _best_effort_deregister(ctx, type_name))

    reg = _poll_until(
        lambda: cfn.describe_type_registration(RegistrationToken=token),
        lambda r: r["ProgressStatus"] in ("COMPLETE", "FAILED"),
        timeout_s=240,
        interval_s=5,
    )
    if reg["ProgressStatus"] != "COMPLETE":
        raise AssertionError(
            "RegisterType did not reach COMPLETE for a RESOURCE provider package: "
            f"{reg.get('Description')}",
        )
    reg["RegistrationToken"] = token
    return reg


def _best_effort_deregister(ctx, type_name: str) -> None:
    """Teardown: deregister non-default versions first, since DeregisterType on a type with more
    than one active version is refused and would strand the type and its handler Lambda."""
    cfn = ctx.client("cloudformation")
    try:
        arn = cfn.describe_type(Type="RESOURCE", TypeName=type_name)["Arn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise
        return
    try:
        default_version = cfn.describe_type(Arn=arn).get("DefaultVersionId")
        for version in cfn.list_type_versions(Arn=arn)["TypeVersionSummaries"]:
            if version["VersionId"] != default_version:
                try:
                    cfn.deregister_type(Arn=version["Arn"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "TypeNotFoundException":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise
    try:
        cfn.deregister_type(Type="RESOURCE", TypeName=type_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
