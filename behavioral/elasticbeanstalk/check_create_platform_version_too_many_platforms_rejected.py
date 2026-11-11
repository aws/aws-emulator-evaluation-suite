"""create-platform-version-too-many-platforms-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# A manifest-less empty ZIP (just the end-of-central-directory record): CreatePlatformVersion
# accepts it, consuming a quota slot, then fails builder validation in seconds without
# provisioning a builder, which makes exhausting the quota cheap.
_EMPTY_ZIP = b"PK\x05\x06" + b"\x00" * 18

CHECK = "create-platform-version-too-many-platforms-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx) -> None:
    """CreatePlatformVersion beyond the account's CustomPlatformQuota returns
    TooManyPlatformsException with no message and registers no platform."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    quota = eb.describe_account_attributes()["ResourceQuotas"]["CustomPlatformQuota"]["Maximum"]
    assert quota is not None, "CustomPlatformQuota.Maximum missing from DescribeAccountAttributes"

    bucket = eb.create_storage_location()["S3Bucket"]
    bundle_key = f"{ctx.unique_name('sim2real-eb-plat-bundle-')}/bundle.zip"
    s3.put_object(Bucket=bucket, Key=bundle_key, Body=_EMPTY_ZIP)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=bundle_key))

    run_prefix = ctx.unique_name("sim2real-eb-plat-")
    platform_arns = []
    ctx.on_cleanup(lambda: _delete_platforms(ctx, platform_arns))
    refused = None
    for i in range(quota + 1):
        try:
            resp = eb.create_platform_version(
                PlatformName=f"{run_prefix}-{i}",
                PlatformVersion="1.0.0",
                PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": bundle_key},
            )
        except ClientError as err:
            refused = (err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
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

    # The refused call registers no platform under its name.
    refused_name = f"{run_prefix}-{len(platform_arns)}"
    listed = _run_platform_arns(eb, run_prefix)
    assert not any(f":platform/{refused_name}/" in arn for arn in listed), (
        f"the refused CreatePlatformVersion {refused_name!r} still registered a platform"
    )


# ===== helpers =====

def _delete_platforms(ctx, platform_arns, timeout_s: float = 600.0) -> None:
    """Delete every created platform under one shared deadline that fits the cleanup budget."""
    eb = ctx.client("elasticbeanstalk")
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


def _run_platform_arns(eb, run_prefix: str) -> set[str]:
    """The ARNs of the custom platforms whose name starts with this run's prefix."""
    arns: set[str] = set()
    kwargs: dict = {"Filters": [
        {"Type": "PlatformName", "Operator": "begins_with", "Values": [f"{run_prefix}-"]},
    ]}
    while True:
        resp = eb.list_platform_versions(**kwargs)
        arns.update(p["PlatformArn"] for p in resp["PlatformSummaryList"])
        token = resp.get("NextToken")
        if not token:
            return arns
        kwargs["NextToken"] = token


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
