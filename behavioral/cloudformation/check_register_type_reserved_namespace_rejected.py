"""register-type-reserved-namespace-rejected."""
from __future__ import annotations

import io
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-type-reserved-namespace-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterType synchronously rejects a TypeName in the reserved AWS namespace with
    CFNRegistryException, while the identical package under a non-reserved TypeName is accepted."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    region = ctx.region

    bucket = ctx.unique_name("sim2real-cfnrsvd-").replace("_", "-").lower()
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    key = "module.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_module_zip_bytes())
    package_url = f"s3://{bucket}/{key}"

    valid_type_name = _valid_type_name(ctx)
    positive = cfn.register_type(
        Type="MODULE", TypeName=valid_type_name, SchemaHandlerPackage=package_url
    )
    assert positive.get(
        "RegistrationToken"
    ), f"expected a non-reserved TypeName to be accepted synchronously, got {positive!r}"
    ctx.on_cleanup(lambda: _best_effort_deregister(cfn, valid_type_name))

    reserved_type_name = "AWS::Behav::ReservedTest::MODULE"

    code, message = _error(
        lambda: cfn.register_type(
            Type="MODULE", TypeName=reserved_type_name, SchemaHandlerPackage=package_url
        )
    )
    assert code == "CFNRegistryException", f"expected a namespace-validation error, got {code}"
    expected = f"Type name {reserved_type_name} is using a restricted namespace aws"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _module_zip_bytes() -> bytes:
    fragment = (
        b'{"AWSTemplateFormatVersion": "2010-09-09", '
        b'"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("module.json", fragment)
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


def _valid_type_name(ctx) -> str:
    suffix = "".join(c for c in ctx.unique_name("x") if c.isalnum())[:16] or "poscontrol"
    return f"Sim2Real{suffix}::Behav{suffix}::PosCtrl::MODULE"


def _best_effort_deregister(cfn, type_name: str) -> None:
    try:
        cfn.deregister_type(Type="MODULE", TypeName=type_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises; raise on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
