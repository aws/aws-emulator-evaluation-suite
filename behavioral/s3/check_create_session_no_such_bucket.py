"""create-session-no-such-bucket."""

from __future__ import annotations
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "create-session-no-such-bucket"
GROUP = 'directory_buckets'
SERVICES = ['s3']

# S3 Express One Zone Availability-Zone ids keyed by region (directory buckets are Zonal).
_S3EXPRESS_AZ_BY_REGION = {
    "us-east-1": ["use1-az4", "use1-az5", "use1-az6"],
    "us-east-2": ["use2-az1", "use2-az2"],
    "us-west-2": ["usw2-az1", "usw2-az3", "usw2-az4"],
    "ap-south-1": ["aps1-az1", "aps1-az3"],
    "ap-northeast-1": ["apne1-az1", "apne1-az4"],
    "eu-central-1": ["euc1-az1", "euc1-az2"],
    "eu-west-1": ["euw1-az1", "euw1-az3"],
    "eu-north-1": ["eun1-az1", "eun1-az2", "eun1-az3"],
}


def _err(fn):
    """Call fn(); return the ClientError (Code, Message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded instead: {result!r}")


def _create_directory_bucket(ctx, s3, base):
    azs = _S3EXPRESS_AZ_BY_REGION.get(ctx.region)
    if not azs:
        raise AssertionError(f"S3 Express One Zone AZ IDs not known for region {ctx.region}")
    last_err = None
    for az in azs:
        bucket = f"{base}--{az}--x-s3"
        try:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            last_err = exc
            continue
        return bucket, az
    raise AssertionError(f"could not create an S3 Express directory bucket in {ctx.region}: {last_err}")


def _delete_directory_bucket(s3, bucket):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []) or []:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSession on a nonexistent directory bucket raises NoSuchBucket with AWS's message,
    while it succeeds on a real one; ListDirectoryBuckets confirms the missing name is absent."""
    s3 = ctx.client("s3")
    if not hasattr(s3, "create_session"):
        raise AssertionError("boto3 s3 client lacks create_session (S3 Express API not available)")

    base = ctx.unique_name("sim2real-behav-sess-").lower().rstrip("-")
    bucket, az = _create_directory_bucket(ctx, s3, base)
    ctx.on_cleanup(lambda: _delete_directory_bucket(s3, bucket))

    # Positive control: CreateSession succeeds on a real directory bucket.
    control = s3.create_session(Bucket=bucket)
    assert control["Credentials"]["AccessKeyId"], "positive control: expected session credentials"

    # The AZ segment must belong to the region under test, otherwise S3 Express endpoint
    # resolution cannot build a resolvable hostname and the request never reaches the service.
    missing = f"{base}-missing--{az}--x-s3"

    listed_before = [b["Name"] for b in s3.list_directory_buckets().get("Buckets", [])]
    assert missing not in listed_before, f"bucket {missing} unexpectedly already present in {listed_before}"

    err = _err(lambda: s3.create_session(Bucket=missing))
    assert err == ("NoSuchBucket", "The specified bucket does not exist."), (
        f"expected NoSuchBucket with AWS's exact message, got {err!r}"
    )

    # Effect absent: an independent read confirms the bucket does not exist.
    listed_after = [b["Name"] for b in s3.list_directory_buckets().get("Buckets", [])]
    assert missing not in listed_after, f"bucket {missing} unexpectedly present in {listed_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
