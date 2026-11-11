"""list-types-filters-by-visibility-and-category."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-types-filters-by-visibility-and-category"
GROUP = "data-plane"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTypes PRIVATE+REGISTERED omits a module whose registration FAILED but lists one that
    completed, and PUBLIC+AWS_TYPES lists only AWS:: types without a PublisherId."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    bucket = _scratch_bucket(ctx, s3)

    failed_type_name = _module_type_name(ctx, "Filt")
    failed_key = "module-package-bad.zip"
    s3.put_object(Bucket=bucket, Key=failed_key, Body=_malformed_module_zip_bytes())

    failed_token = cfn.register_type(
        Type="MODULE", TypeName=failed_type_name, SchemaHandlerPackage=f"s3://{bucket}/{failed_key}"
    )["RegistrationToken"]
    ctx.on_cleanup(lambda: _try_deregister(cfn, failed_type_name))

    described = _poll_registration(cfn, failed_token)
    assert described["ProgressStatus"] == "FAILED", f"expected deterministic FAILED, got: {described}"

    # A registration that never completed must not surface as a registered private type.
    private_registered = cfn.list_types(
        Visibility="PRIVATE", Type="MODULE", Filters={"Category": "REGISTERED"}
    )["TypeSummaries"]
    assert not any(t["TypeName"] == failed_type_name for t in private_registered), (
        f"expected {failed_type_name} (registration FAILED) absent from PRIVATE+REGISTERED, "
        f"found it in {private_registered}"
    )

    # Twin control: without a completed module listed under the same filter, the negative
    # above is indistinguishable from a filter combination that never returns anything.
    complete_type_name = _module_type_name(ctx, "Comp")
    complete_key = "module-package-good.zip"
    s3.put_object(
        Bucket=bucket, Key=complete_key, Body=_valid_module_zip_bytes(complete_type_name)
    )
    ctx.on_cleanup(lambda: _try_deregister(cfn, complete_type_name))
    complete_reg = _register_type_and_wait(cfn, complete_type_name, f"s3://{bucket}/{complete_key}")
    assert complete_reg["ProgressStatus"] == "COMPLETE", (
        f"expected the well-formed module {complete_type_name} to COMPLETE, got: {complete_reg}"
    )

    private_registered_after = cfn.list_types(
        Visibility="PRIVATE", Type="MODULE", Filters={"Category": "REGISTERED"}
    )["TypeSummaries"]
    assert any(t["TypeName"] == complete_type_name for t in private_registered_after), (
        f"expected completed module {complete_type_name} present in PRIVATE+REGISTERED, "
        f"got {private_registered_after}"
    )

    # AWS-published types in the PUBLIC+AWS_TYPES catalog carry no PublisherId.
    public_aws_types = cfn.list_types(
        Visibility="PUBLIC",
        Type="RESOURCE",
        Filters={"Category": "AWS_TYPES"},
        MaxResults=50,
    )["TypeSummaries"]
    assert len(public_aws_types) > 0, "expected a non-empty PUBLIC+AWS_TYPES catalog"
    assert all(t["TypeName"].startswith("AWS::") for t in public_aws_types), public_aws_types
    assert all("PublisherId" not in t for t in public_aws_types), public_aws_types




def _module_type_name(ctx, tag):
    token = "".join(ch for ch in ctx.unique_name(tag) if ch.isalnum())
    if len(token) < 2:
        token = (token + "abcdefgh")[:8]
    token = token[:40]
    return f"S2R{tag[:6].capitalize()}::{token}::Behav::MODULE"


def _malformed_module_zip_bytes():
    # Deliberately incomplete: a MODULE package needs a top-level schema.json alongside
    # fragments/fragment.json, so registration fails at VALIDATION_STAGE with
    # "files are missing from the input artifact: [schema.json]".
    fragment = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "sim2real behavioral fidelity test module fragment",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("fragments/fragment.json", json.dumps(fragment))
    return buf.getvalue()


def _valid_module_zip_bytes(type_name):
    # The package shape a MODULE registration needs to reach COMPLETE:
    # fragments/fragment.json plus a top-level schema.json.
    fragment = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "sim2real behavioral fidelity test module fragment",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    schema = {
        "typeName": type_name,
        "description": "sim2real behavioral fidelity test module fragment",
        "properties": {"Resources": {"type": "object"}},
        "additionalProperties": True,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("fragments/fragment.json", json.dumps(fragment))
        zf.writestr("schema.json", json.dumps(schema))
    return buf.getvalue()


def _scratch_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-behav-cfn-mod-")
    # S3's own CreateBucket quirk, not a resource region pin: us-east-1 rejects an
    # explicit LocationConstraint, every other region requires one. bucket placement
    # still follows ctx.region either way.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup_bucket():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for o in objs:
                s3.delete_object(Bucket=bucket, Key=o["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup_bucket)
    return bucket


def _try_deregister(cfn, type_name):
    try:
        cfn.deregister_type(Type="MODULE", TypeName=type_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


def _poll_registration(cfn, token, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = cfn.describe_type_registration(RegistrationToken=token)
        if described["ProgressStatus"] in ("COMPLETE", "FAILED"):
            return described
        time.sleep(interval_s)
    raise AssertionError(f"registration {token} did not reach a terminal state within {timeout_s}s")


def _register_type_and_wait(cfn, type_name, schema_handler_package, *, max_attempts=3, timeout_s=180.0, interval_s=5.0):
    # MODULE registration's async VALIDATION_STAGE occasionally lands in FAILED on real
    # AWS well before it would time out (transient validation-infra hiccup rather than a
    # real package problem); a bounded retry of the whole register+poll cycle makes the
    # completion leg robust without weakening the COMPLETE assertion.
    last = None
    for _ in range(max_attempts):
        token = cfn.register_type(
            Type="MODULE", TypeName=type_name, SchemaHandlerPackage=schema_handler_package
        )["RegistrationToken"]
        reg = _poll_registration(cfn, token, timeout_s=timeout_s, interval_s=interval_s)
        if reg["ProgressStatus"] == "COMPLETE":
            return reg
        last = reg
    raise AssertionError(
        f"registration for {type_name} did not COMPLETE after {max_attempts} attempts; last={last}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
