"""create-platform-version-quota-exceeded-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_EMPTY_ZIP = b"PK\x05\x06" + b"\x00" * 18

CHECK = "create-platform-version-quota-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx) -> None:
    """CreatePlatformVersion beyond the account's CustomPlatformQuota raises TooManyPlatformsException
    and creates no platform version, while other Elastic Beanstalk calls keep working."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    quota = eb.describe_account_attributes()["ResourceQuotas"]["CustomPlatformQuota"]["Maximum"]
    assert quota is not None, "CustomPlatformQuota.Maximum missing from DescribeAccountAttributes"

    bucket = eb.create_storage_location()["S3Bucket"]
    key = ctx.unique_name("sim2real-ebpq-bundle-") + ".zip"
    # A manifest-less empty ZIP is accepted and consumes a quota slot, then fails builder
    # validation in seconds without provisioning a builder, so the quota is cheap to exhaust.
    s3.put_object(Bucket=bucket, Key=key, Body=_EMPTY_ZIP)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    platform_arns: list[str] = []
    ctx.on_cleanup(lambda: _delete_platforms(eb, platform_arns))
    platform_name = None
    code = None
    for i in range(quota + 1):
        platform_name = ctx.unique_name(f"sim2real-ebpq-plat{i}-")
        try:
            resp = eb.create_platform_version(
                PlatformName=platform_name,
                PlatformVersion="1.0.0",
                PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": key},
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            break
        platform_arns.append(resp["PlatformSummary"]["PlatformArn"])
    assert code is not None, (
        f"all {quota + 1} CreatePlatformVersion calls were accepted against a CustomPlatformQuota "
        f"of {quota}"
    )
    assert code == "TooManyPlatformsException", f"expected TooManyPlatformsException, got {code}"

    # (b) effect absent: no new platform version with this name exists
    found = eb.list_platform_versions(
        Filters=[{"Type": "PlatformName", "Operator": "=", "Values": [platform_name]}]
    )["PlatformSummaryList"]
    assert found == [], f"expected no platform version created, found {found}"

    # (c) positive control: the API remains functional for a non-platform-creating call
    apps = eb.describe_applications()
    assert "Applications" in apps, f"expected DescribeApplications to keep working, got {apps!r}"


def _delete_platforms(eb, platform_arns, timeout_s: float = 600.0) -> None:
    """Delete every created platform under one shared deadline that fits the cleanup budget."""
    deadline = time.monotonic() + timeout_s
    for arn in platform_arns:
        _delete_platform(eb, arn, timeout_s=max(1.0, deadline - time.monotonic()))


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
