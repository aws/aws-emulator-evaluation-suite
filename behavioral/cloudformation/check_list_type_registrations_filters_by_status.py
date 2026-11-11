"""list-type-registrations-filters-by-status."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-type-registrations-filters-by-status"
GROUP = "data-plane"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A registration that ends FAILED (its module package is incomplete) is listed by ListTypeRegistrations
    under RegistrationStatusFilter=FAILED for its TypeName and excluded under COMPLETE."""
    cfn = ctx.client("cloudformation")
    type_name = _module_type_name(ctx, "Status")
    package_url = _scratch_bucket_with_module_package(ctx, type_name)

    token = cfn.register_type(
        Type="MODULE", TypeName=type_name, SchemaHandlerPackage=package_url
    )["RegistrationToken"]
    ctx.on_cleanup(lambda: cfn.deregister_type(Type="MODULE", TypeName=type_name))

    described = _poll_registration(cfn, token)
    assert described["ProgressStatus"] == "FAILED", f"expected deterministic FAILED, got: {described}"

    failed_tokens = cfn.list_type_registrations(
        TypeName=type_name, Type="MODULE", RegistrationStatusFilter="FAILED"
    )["RegistrationTokenList"]
    assert token in failed_tokens, f"expected {token} among FAILED-filtered registrations, got: {failed_tokens}"

    complete_tokens = cfn.list_type_registrations(
        TypeName=type_name, Type="MODULE", RegistrationStatusFilter="COMPLETE"
    )["RegistrationTokenList"]
    assert token not in complete_tokens, (
        f"expected {token} excluded from COMPLETE-filtered registrations, got: {complete_tokens}"
    )


def _module_type_name(ctx, tag):
    token = "".join(ch for ch in ctx.unique_name(tag) if ch.isalnum())
    if len(token) < 2:
        token = (token + "abcdefgh")[:8]
    token = token[:40]
    return f"S2R{tag[:6].capitalize()}::{token}::Behav::MODULE"


def _module_fragment_zip(cfn, type_name):
    # Deliberately incomplete package (fragment only, no schema.json/docs) -- this
    # deterministically fails CloudFormation's registry package validation at
    # VALIDATION_STAGE, giving a fast, reliable terminal FAILED registration to exercise
    # status-filtering semantics without depending on a fully valid, deployable module.
    fragment = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "sim2real behavioral fidelity test module fragment",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("fragments/fragment.json", json.dumps(fragment))
    return buf.getvalue()


def _scratch_bucket_with_module_package(ctx, type_name):
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cfn-mod-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup_bucket():
        try:
            s3.delete_object(Bucket=bucket, Key="module-package.zip")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_object(Bucket=bucket, Key="module-package.zip", Body=_module_fragment_zip(cfn, type_name))
    return f"s3://{bucket}/module-package.zip"


def _poll_registration(cfn, token, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = cfn.describe_type_registration(RegistrationToken=token)
        if described["ProgressStatus"] in ("COMPLETE", "FAILED"):
            return described
        time.sleep(interval_s)
    raise AssertionError(f"registration {token} did not reach a terminal state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
