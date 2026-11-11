"""register-type-invalid-schema-rejected."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-type-invalid-schema-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterType accepts a schema-only SchemaHandlerPackage with a token, then the registration
    FAILS asynchronously with an artifact-completeness error and the type never resolves.
    """
    cfn = ctx.client("cloudformation")
    bucket = _create_bucket(ctx)

    # Positive control: a FAILED registration below is not a blanket denial.
    healthy = cfn.list_types(Visibility="PRIVATE", Type="RESOURCE", MaxResults=10)
    assert "TypeSummaries" in healthy, f"expected ListTypes to succeed, got {healthy}"

    bad_type_name = _type_name(ctx, "BadWidget")
    bad_schema = {
        "typeName": bad_type_name,
        "description": "sim2real behavioral test resource with an invalid schema",
        "additionalProperties": False,
        "properties": {"Id": {"type": "string"}},
        # Missing the required "primaryIdentifier"; AWS rejects a schema-only package for missing
        # artifacts (.rpdk-config, handler package) before validating schema content, whatever it is.
    }
    bad_key = "bad-schema-package.zip"
    ctx.client("s3").put_object(Bucket=bucket, Key=bad_key, Body=_build_schema_zip(bad_schema))

    reg = cfn.register_type(
        Type="RESOURCE",
        TypeName=bad_type_name,
        SchemaHandlerPackage=f"s3://{bucket}/{bad_key}",
    )
    # Schema validation is asynchronous, so the call itself always returns a token.
    assert reg["RegistrationToken"], "expected RegisterType to return a RegistrationToken"

    bad_detail = _wait_registration_terminal(ctx, reg["RegistrationToken"])
    assert bad_detail["ProgressStatus"] == "FAILED", (
        f"expected registration to FAIL for a schema-only package, got "
        f"{bad_detail['ProgressStatus']}: {bad_detail.get('Description')}"
    )
    # The Description embeds a per-registration id, e.g. "... Error message: [<uuid>] One or more of the following files are missing from
    # the input artifact: [schema.json, .rpdk-config, lambda deployment package]".
    description = (bad_detail.get("Description") or "").lower()
    assert "missing" in description and "artifact" in description, (
        f"expected an artifact-completeness rejection, got: {bad_detail.get('Description')!r}"
    )

    not_found_code, not_found_message = _error(lambda: cfn.describe_type(Type="RESOURCE", TypeName=bad_type_name))
    assert not_found_code == "TypeNotFoundException", f"expected TypeNotFoundException, got {not_found_code}"
    expected = f"The type '{bad_type_name}' cannot be found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    reg_detail = cfn.describe_type_registration(RegistrationToken=reg["RegistrationToken"])
    assert reg_detail["ProgressStatus"] == "FAILED", reg_detail


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises; raise on success."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _type_name(ctx, resource_word: str) -> str:
    raw = ctx.unique_name("x")
    suffix = re.sub(r"[^A-Za-z0-9]", "", raw)
    suffix = suffix[-16:] if len(suffix) > 16 else suffix
    return f"Sim2Real{suffix}::Behav::{resource_word}"


def _build_schema_zip(schema: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("schema.json", json.dumps(schema))
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfn-regtype-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _wait_registration_terminal(ctx, token, timeout_s=240.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_type_registration(RegistrationToken=token)
        if last["ProgressStatus"] in ("COMPLETE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"registration {token} never reached a terminal state, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

