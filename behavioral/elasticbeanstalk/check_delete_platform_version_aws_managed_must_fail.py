"""delete-platform-version-aws-managed-must-fail."""
from __future__ import annotations

import io
import time
import zipfile
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-platform-version-aws-managed-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']


def _delete_error(fn: Callable[[], Any]) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    over-permissive target ACCEPTING a call real AWS refuses is the strongest signal available
    and must not be reported as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _wait_platform_terminal(eb, platform_arn: str, *, timeout_s: float = 1200.0, interval_s: float = 20.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = eb.describe_platform_version(PlatformArn=platform_arn)["PlatformDescription"]["PlatformStatus"]
        if status in ("Ready", "Failed"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"platform build did not reach a terminal status within {timeout_s}s; last saw {status!r}")


def _wait_platform_deleted(eb, platform_arn: str, *, timeout_s: float = 180.0, interval_s: float = 10.0) -> None:
    """DeletePlatformVersion is asynchronous: PlatformStatus moves Ready/Failed -> Deleting ->
    Deleted (all modeled PlatformStatus values), rather than the platform vanishing on the spot.
    Bounded poll on the target's own reported state, not a sleep."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = eb.describe_platform_version(PlatformArn=platform_arn)["PlatformDescription"]["PlatformStatus"]
        except ClientError:
            return
        if last == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"deleted platform version did not reach Deleted within {timeout_s}s; last saw {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx) -> None:
    """DeletePlatformVersion must refuse to delete an AWS-managed platform version, while the
    same operation succeeds for a custom platform version this check owns — the positive control
    that separates "AWS-managed deletes are refused" from "every delete is refused"."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    # --- positive control: DeletePlatformVersion succeeds against a custom platform ---
    bucket = eb.create_storage_location()["S3Bucket"]
    platform_name = ctx.unique_name("sim2real-eb-plat-")
    key = f"{platform_name}/platform-definition.zip"
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=_build_minimal_platform_bundle(),
        Tagging=f"sim2real-check={CHECK}",
    )
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    own_arn = eb.create_platform_version(
        PlatformName=platform_name,
        PlatformVersion="1.0.0",
        PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": key},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["PlatformSummary"]["PlatformArn"]
    ctx.on_cleanup(lambda: _delete_platform(eb, own_arn))

    status = _wait_platform_terminal(eb, own_arn)
    assert status in ("Ready", "Failed"), f"unexpected terminal PlatformStatus {status!r} for own platform"

    eb.delete_platform_version(PlatformArn=own_arn)
    _wait_platform_deleted(eb, own_arn)

    # --- the negative under test: an AWS-managed platform version must survive the same call ---
    listed = eb.list_platform_versions(
        Filters=[{"Type": "PlatformOwner", "Operator": "=", "Values": ["AWSElasticBeanstalk"]}],
        MaxRecords=1,
    )["PlatformSummaryList"]
    if not listed:
        raise AssertionError("no AWS-managed platform versions available")
    arn = listed[0]["PlatformArn"]

    error = _delete_error(lambda: eb.delete_platform_version(PlatformArn=arn))
    assert error["Code"] == "InvalidParameterValue", (
        f"deleting an AWS-managed platform version must be refused with InvalidParameterValue, "
        f"got {error['Code']!r} ({error.get('Message')!r})"
    )
    expected = f"Platform '{arn}' does not belong to your account."
    assert error.get("Message") == expected, (
        f"refusal must be the AWS-managed-platform-ownership rejection {expected!r}, "
        f"got {error.get('Message')!r}"
    )

    still_there = eb.describe_platform_version(PlatformArn=arn)["PlatformDescription"]
    assert still_there["PlatformArn"] == arn, (
        "the AWS-managed platform version must survive the refused delete"
    )


# ===== helpers =====
def _build_minimal_platform_bundle() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "platform.yaml",
            "version: 1\n"
            "provisioner:\n"
            "  type: packer\n"
            "executables: {}\n",
        )
        zf.writestr("Dockerfile", "FROM scratch\n")
    return buf.getvalue()


def _delete_platform(eb, platform_arn: str, timeout_s: float = 600.0) -> None:
    """Delete a custom platform once its build is terminal, retrying OperationInProgressFailure
    every 2 s; a Deleting/Deleted or not-found platform is already gone, anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = eb.describe_platform_version(PlatformArn=platform_arn)["PlatformDescription"]["PlatformStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValue" and "found" in err.get("Message", "").lower():
                return
            raise
        if status in ("Deleting", "Deleted"):
            return
        if status in ("Ready", "Failed"):
            try:
                eb.delete_platform_version(PlatformArn=platform_arn)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "OperationInProgressFailure":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"platform {platform_arn} still {status!r} after {timeout_s}s, not deleted")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
