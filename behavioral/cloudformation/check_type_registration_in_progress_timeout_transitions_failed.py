"""type-registration-in-progress-timeout-transitions-failed."""
from __future__ import annotations

import io
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-registration-in-progress-timeout-transitions-failed"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unissued registration token is rejected with CFNRegistryException, and registering a
    package with no schema.json ends FAILED with a Description and no resolvable type.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    # A registration token that was never issued is unknown to the registry.
    bogus_token = f"sim2real-{uuid.uuid4().hex}"
    error = _error(lambda: cfn.describe_type_registration(RegistrationToken=bogus_token))
    expected = ("CFNRegistryException", "UUID is invalid")
    assert error == expected, f"expected {expected!r} for an unissued registration token, got {error!r}"

    bucket = ctx.unique_name("sim2real-cfn-typereg-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    package_url = _put_dummy_package(s3, bucket)
    type_name = f"Sim2Real::TypeReg{uuid.uuid4().hex[:10]}::Widget"

    token = cfn.register_type(
        Type="RESOURCE", TypeName=type_name, SchemaHandlerPackage=package_url
    )["RegistrationToken"]

    status, description = _poll_registration_terminal(cfn, token, timeout_s=300)
    assert status == "FAILED", f"expected registration to FAIL for a package with no schema.json, got {status}"
    # message varies: the FAILED Description embeds a per-deployment request id.
    assert description, "a FAILED registration must carry a non-empty StatusReason/Description"

    # Effect-absent: a FAILED registration never produces a resolvable type. An independent
    # read (DescribeType, not DescribeTypeRegistration) confirms the type name never registered.
    not_found = _error(lambda: cfn.describe_type(Type="RESOURCE", TypeName=type_name))
    expected_not_found = ("TypeNotFoundException", f"The type '{type_name}' cannot be found.")
    assert not_found == expected_not_found, (
        f"expected {expected_not_found!r} for a type whose only registration FAILED, got {not_found!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup() -> None:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _put_dummy_package(s3, bucket: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real placeholder schema handler package\n")
    s3.put_object(Bucket=bucket, Key="package.zip", Body=buf.getvalue())
    return f"s3://{bucket}/package.zip"


def _poll_registration_terminal(cfn, token: str, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_type_registration(RegistrationToken=token)
        last_status = resp.get("ProgressStatus")
        if last_status in ("COMPLETE", "FAILED"):
            return last_status, resp.get("Description")
        time.sleep(interval_s)
    raise AssertionError(f"registration {token} never reached a terminal status, last={last_status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
