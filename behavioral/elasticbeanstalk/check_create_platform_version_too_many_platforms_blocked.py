"""create-platform-version-too-many-platforms-blocked."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-platform-version-too-many-platforms-blocked"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]

_PLATFORM_TAGS = [{"Key": "sim2real", "Value": "true"}]

# A manifest-less empty ZIP (just the end-of-central-directory record).
_EMPTY_ZIP = b"PK\x05\x06" + b"\x00" * 18


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx) -> None:
    """CreatePlatformVersion beyond the account's live CustomPlatformQuota is rejected with
    TooManyPlatformsException and creates no platform version, while deleting one existing custom
    platform makes the identical kind of create succeed again.
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    quota = eb.describe_account_attributes()["ResourceQuotas"]["CustomPlatformQuota"]["Maximum"]
    assert quota is not None, "CustomPlatformQuota.Maximum missing from DescribeAccountAttributes"

    bucket = ctx.unique_name("sim2real-eb-platbundle-").lower()
    key = "platform.zip"
    _create_bucket(ctx, s3, bucket)
    # An empty bundle with no platform.yaml fails builder validation within seconds and never provisions
    # a builder environment, so the real CustomPlatformQuota is cheap to exhaust.
    s3.put_object(Bucket=bucket, Key=key, Body=_EMPTY_ZIP)

    def _create(name):
        return eb.create_platform_version(
            PlatformName=name,
            PlatformVersion="1.0.0",
            PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": key},
            Tags=_PLATFORM_TAGS,
        )

    filler_arns = []
    over_name = None
    code = None
    for i in range(quota + 1):
        over_name = ctx.unique_name(f"sim2real-fill-plat{i}-")
        try:
            resp = _create(over_name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            break
        arn = resp["PlatformSummary"]["PlatformArn"]
        ctx.on_cleanup(lambda a=arn: _wait_terminal_then_delete(eb, a))
        filler_arns.append(arn)
    assert code is not None, (
        f"all {quota + 1} CreatePlatformVersion calls were accepted against a CustomPlatformQuota "
        f"of {quota}"
    )
    assert code == "TooManyPlatformsException", code
    assert filler_arns, "the first CreatePlatformVersion was refused; no platform of this run frees a slot"

    # Effect absent: no platform version record exists for the rejected name.
    listed = eb.list_platform_versions(
        Filters=[{"Type": "PlatformName", "Operator": "=", "Values": [over_name]}]
    )["PlatformSummaryList"]
    assert listed == [], f"expected no platform version named {over_name!r} after the rejected create, found {listed!r}"

    # Positive control: free exactly one slot (wait for its build to reach a terminal state, then
    # delete it), and the identical kind of create succeeds again once the deletion releases it.
    freed_arn = filler_arns[0]
    _wait_terminal_then_delete(eb, freed_arn)
    filler_arns.remove(freed_arn)

    retry_name = ctx.unique_name("sim2real-plat-retry-")
    deadline = time.monotonic() + _budget_s(ctx, 300.0)
    while True:
        try:
            retry_resp = _create(retry_name)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "TooManyPlatformsException" or time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("run budget ended before the freed platform slot was released") from e
                raise
        time.sleep(2)
    retry_arn = retry_resp["PlatformSummary"]["PlatformArn"]
    ctx.on_cleanup(lambda: _wait_terminal_then_delete(eb, retry_arn))
    # The create response's PlatformSummary carries no PlatformName; the ARN names the platform.
    got_name = retry_arn.split(":platform/", 1)[1].split("/", 1)[0]
    assert got_name == retry_name, f"expected the identical retried create to succeed as {retry_name!r}, got {got_name!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_terminal_then_delete(eb, platform_arn, timeout_s=600.0, interval_s=2.0):
    """Delete a custom platform once its build is terminal; a Deleting/Deleted or not-found
    platform is already gone, anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = eb.describe_platform_version(PlatformArn=platform_arn)["PlatformDescription"]["PlatformStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "").lower()
            if err["Code"] == "InvalidParameterValue" and ("found" in message or "does not exist" in message):
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
        time.sleep(interval_s)


def _create_bucket(ctx, s3, bucket):
    kwargs = {"Bucket": bucket}
    # S3 quirk, not a region pin: CreateBucket rejects an explicit LocationConstraint of
    # "us-east-1" (it is the implicit default), so the constraint is omitted only there.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket):
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
