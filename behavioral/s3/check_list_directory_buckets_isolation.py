"""list-directory-buckets-isolation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-directory-buckets-isolation"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDirectoryBuckets returns only directory (Express) buckets, excluding general-purpose buckets."""
    s3 = ctx.client("s3")
    gp_bucket = ctx.unique_name("sim2real-gp-")
    _create_bucket(s3, ctx, gp_bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=gp_bucket))

    dir_bucket = _create_directory_bucket(ctx)

    gp_listed = {b["Name"] for b in s3.list_buckets().get("Buckets", [])}
    assert gp_bucket in gp_listed, f"expected {gp_bucket} in ListBuckets output"
    assert dir_bucket not in gp_listed, f"directory bucket {dir_bucket} leaked into ListBuckets"

    dir_listed = {b["Name"] for b in s3.list_directory_buckets().get("Buckets", [])}
    assert dir_bucket in dir_listed, f"expected {dir_bucket} in ListDirectoryBuckets output"
    assert gp_bucket not in dir_listed, f"general-purpose bucket {gp_bucket} leaked into ListDirectoryBuckets"


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    # us-east-1 is S3's original region: CreateBucket rejects an explicit LocationConstraint there.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _safe(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_directory_bucket(ctx):
    s3 = ctx.client("s3")
    ec2 = ctx.client("ec2")
    try:
        azs = ec2.describe_availability_zones(
            Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    except Exception as exc:
        raise AssertionError(f"cannot discover availability zones for S3 Express: {exc}") from exc
    az_ids = [az["ZoneId"] for az in azs if az.get("ZoneId")]
    if not az_ids:
        raise AssertionError("no availability-zone id discovered for S3 Express directory bucket")

    base = ctx.unique_name("sim2realdb").rstrip("-").replace("_", "-").lower()
    attempts: list[str] = []
    for az_id in az_ids:
        bucket = f"{base}--{az_id}--x-s3"
        try:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az_id},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            attempts.append(f"{az_id}: {exc}")
            continue
        ctx.on_cleanup(lambda bucket=bucket: _delete_directory_bucket(s3, bucket))
        return bucket
    raise AssertionError(
        "S3 Express directory buckets unavailable in this environment across all "
        f"{len(az_ids)} discovered availability zone(s): " + "; ".join(attempts)
    )


def _delete_directory_bucket(s3, bucket):
    try:
        listed = s3.list_objects_v2(Bucket=bucket)
        for obj in listed.get("Contents", []):
            _safe(s3.delete_object, Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    _safe(s3.delete_bucket, Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
