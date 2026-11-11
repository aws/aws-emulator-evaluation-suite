"""type-version-publish-before-test-rejected."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-version-publish-before-test-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """PublishType refuses a type-version Arn outright -- only the type's own, unversioned
    Arn naming its current default version is publishable -- both before and after TestType
    runs; TestType remains independently exercisable and never makes the type public."""
    cfn = ctx.client("cloudformation")
    bucket = _create_bucket(ctx)
    type_name = _unique_type_name(ctx)
    schema = _minimal_schema(type_name)

    reg = _register_resource_type(ctx, bucket, type_name, schema)
    type_arn = reg["TypeArn"]
    version_arn = reg["TypeVersionArn"]

    versions = cfn.list_type_versions(Arn=type_arn)["TypeVersionSummaries"]
    assert len(versions) == 1, (
        f"expected exactly 1 registered version, got {len(versions)}: {versions}"
    )
    assert versions[0]["Arn"] == version_arn, (
        f"expected the only listed version to be {version_arn!r}, got {versions[0]['Arn']!r}"
    )

    # PublishType only ever publishes a type's current default version, so a version-specific
    # Arn is refused outright -- independent of test status or publisher registration.
    expected_publish_error = (
        "CFNRegistryException",
        "Only default version can be published. Please remove versionId from Arn",
    )
    publish_error = _error(lambda: cfn.publish_type(Arn=version_arn))
    assert publish_error == expected_publish_error, (
        f"expected {expected_publish_error!r} from PublishType on a type-version Arn, "
        f"got {publish_error!r}"
    )

    # Effect-absent: the rejected PublishType must not have taken effect. An independent
    # read of the type shows it is still private, with no public version recorded.
    described_after_reject = cfn.describe_type(Arn=type_arn)
    assert described_after_reject.get("Visibility", "PRIVATE") == "PRIVATE", (
        f"expected type to remain PRIVATE after a rejected PublishType, "
        f"got Visibility={described_after_reject.get('Visibility')!r}"
    )
    assert not described_after_reject.get("LatestPublicVersion"), (
        f"expected no LatestPublicVersion after a rejected PublishType, "
        f"got {described_after_reject.get('LatestPublicVersion')!r}"
    )

    # TestType is still exercisable on the version Arn: it either kicks off contract
    # testing (polled here to a terminal status) or is synchronously refused with the
    # same registry-gate error family -- either way the attempt itself is not blocked
    # by the earlier rejected PublishType call.
    try:
        test_resp = cfn.test_type(Arn=version_arn)
        assert test_resp["TypeVersionArn"] == version_arn
        final = _poll_until(
            lambda: cfn.describe_type(Arn=type_arn),
            lambda d: (
                d.get("TypeTestsStatus") not in (None, "IN_PROGRESS", "NOT_TESTED")
            ),
            timeout_s=90,
            interval_s=5,
            allow_timeout=True,
        )
        if final is not None:
            assert final.get("TypeTestsStatus") in ("PASSED", "FAILED")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "CFNRegistryException"

    # The same version-specific Arn is refused identically after TestType has run.
    publish_error_2 = _error(lambda: cfn.publish_type(Arn=version_arn))
    assert publish_error_2 == expected_publish_error, (
        f"expected {expected_publish_error!r} from the post-TestType publish attempt, "
        f"got {publish_error_2!r}"
    )

    # Effect-absent, again, after TestType has run: still no public version.
    described_final = cfn.describe_type(Arn=type_arn)
    assert described_final.get("Visibility", "PRIVATE") == "PRIVATE", (
        f"expected type to remain PRIVATE after the second rejected PublishType, "
        f"got Visibility={described_final.get('Visibility')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, allow_timeout=False):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() > deadline:
            if allow_timeout:
                return None
            raise AssertionError(
                f"condition not met within {timeout_s}s; last result={result}"
            )
        time.sleep(interval_s)
        result = probe()
    return result


def _unique_type_name(ctx) -> str:
    suffix = ctx.unique_name("x").replace("-", "").replace("_", "")
    suffix = "".join(c for c in suffix if c.isalnum())[:20] or "abc123"
    return f"Sim2real{suffix}::Behav::Gadget"


def _minimal_schema(type_name: str) -> dict:
    return {
        "typeName": type_name,
        "description": "Simparity behavioral fidelity test resource (schema-only, non-provisionable).",
        "properties": {
            "Id": {"description": "Identifier", "type": "string"},
            "Name": {"description": "Name", "type": "string"},
        },
        "primaryIdentifier": ["/properties/Id"],
        "readOnlyProperties": ["/properties/Id"],
        "createOnlyProperties": ["/properties/Name"],
        "additionalProperties": False,
    }


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfnreg-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    # The registry fetches the package as resources.cloudformation.amazonaws.com, not the
    # calling principal; without this grant RegisterType never reaches COMPLETE.
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


def _resource_package_bytes(type_name: str, schema: dict) -> bytes:
    # RegisterType's VALIDATION_STAGE rejects a bare schema.json for Type="RESOURCE" with
    # "One or more of the following files are missing from the input artifact": it requires
    # the full cloudformation-cli package shape -- schema.json, .rpdk-config and a lambda
    # deployment package -- even for a schema that declares no handlers. The handler is never
    # invoked (the schema has no handlers, so the type registers NON_PROVISIONABLE), so it is
    # a stub.
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


def _register_resource_type(ctx, bucket: str, type_name: str, schema: dict) -> dict:
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    key = f"packages/{type_name.replace('::', '-')}.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_resource_package_bytes(type_name, schema))

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
            f"RegisterType did not reach COMPLETE for a handler-less RESOURCE package: "
            f"{reg.get('Description')}",
        )
    return reg


def _best_effort_deregister(ctx, type_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.deregister_type(Type="RESOURCE", TypeName=type_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
