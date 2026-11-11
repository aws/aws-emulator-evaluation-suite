"""create-platform-version-too-many-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-platform-version-too-many-fails"
GROUP = "error-semantics"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx) -> None:
    """CreatePlatformVersion beyond the account's CustomPlatformQuota fails with
    TooManyPlatformsException, and the rejected call registers no platform."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    quota = eb.describe_account_attributes()["ResourceQuotas"]["CustomPlatformQuota"]["Maximum"]
    assert quota is not None, "CustomPlatformQuota.Maximum missing from DescribeAccountAttributes"

    bucket = eb.create_storage_location()["S3Bucket"]
    key_prefix = ctx.unique_name("sim2real-eb-platform-bundle-")
    bundle_key = f"{key_prefix}/bundle.zip"
    # An empty bundle with no platform.yaml fails builder validation within seconds and never
    # provisions a builder environment, so the real CustomPlatformQuota is cheap to exhaust.
    s3.put_object(Bucket=bucket, Key=bundle_key, Body=b"PK\x05\x06" + b"\x00" * 18)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=bundle_key))

    platform_arns = []
    ctx.on_cleanup(lambda: _delete_platforms(eb, platform_arns))
    over_name = None
    refused = None
    for i in range(quota + 1):
        over_name = ctx.unique_name(f"sim2real-eb-plat{i}-")
        try:
            resp = eb.create_platform_version(
                PlatformName=over_name,
                PlatformVersion="1.0.0",
                PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": bundle_key},
            )
        except ClientError as exc:
            refused = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
            break
        platform_arns.append(resp["PlatformSummary"]["PlatformArn"])
    assert refused is not None, (
        f"all {quota + 1} CreatePlatformVersion calls were accepted against a CustomPlatformQuota "
        f"of {quota}"
    )

    code, message = refused
    assert code == "TooManyPlatformsException", (
        f"expected TooManyPlatformsException once the account holds {quota} custom platforms, "
        f"got {code!r}: {message!r}"
    )
    # AWS's TooManyPlatformsException error carries no Message element, so the message reads empty.
    assert message == "", (
        f"over-quota CreatePlatformVersion must carry no error message, got {message!r}"
    )

    remaining = eb.list_platform_versions(
        Filters=[{"Type": "PlatformName", "Operator": "=", "Values": [over_name]}]
    )["PlatformSummaryList"]
    assert not remaining, f"rejected over-quota create {over_name!r} still registered a platform"


def _delete_platforms(eb, platform_arns, timeout_s: float = 600.0):
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
