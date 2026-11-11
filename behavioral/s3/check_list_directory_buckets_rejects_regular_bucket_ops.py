"""list-directory-buckets-rejects-regular-bucket-ops."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-directory-buckets-rejects-regular-bucket-ops"
GROUP = "overly-permissive"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A general-purpose bucket appears in ListBuckets but never in ListDirectoryBuckets, while a
    real S3 Express directory bucket does appear there."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    dir_bucket = _create_directory_bucket(ctx)

    all_buckets = {b["Name"] for b in s3.list_buckets().get("Buckets", [])}
    assert bucket in all_buckets, f"sanity check failed: {bucket} missing from ListBuckets"

    directory_bucket_names: set[str] = set()
    token = None
    for _ in range(50):  # bounded pagination guard
        kwargs = {"MaxDirectoryBuckets": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_directory_buckets(**kwargs)
        directory_bucket_names.update(b["Name"] for b in resp.get("Buckets", []))
        token = resp.get("ContinuationToken")
        if not token:
            break

    # Positive control: the listing is populated, not trivially empty.
    assert dir_bucket in directory_bucket_names, (
        f"directory bucket {dir_bucket} missing from ListDirectoryBuckets result "
        f"{sorted(directory_bucket_names)} (cannot distinguish correct scoping from an "
        "unimplemented, always-empty ListDirectoryBuckets)"
    )
    assert bucket not in directory_bucket_names, (
        f"general-purpose bucket {bucket} incorrectly appeared in ListDirectoryBuckets "
        f"result (directory-bucket-only namespace leaked general-purpose bucket)"
    )
    # A general-purpose bucket also never carries the directory-bucket naming suffix.
    assert not bucket.endswith("--x-s3"), f"unexpected directory-bucket-style name: {bucket}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-s3-")
    kwargs: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _create_directory_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    ec2 = ctx.client("ec2")
    try:
        azs = ec2.describe_availability_zones(
            Filters=[
                {"Name": "region-name", "Values": [ctx.region]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"cannot discover availability zones for S3 Express: {exc}") from exc
    az_ids = [az["ZoneId"] for az in azs if az.get("ZoneId")]
    if not az_ids:
        raise AssertionError("no availability-zone id discovered for S3 Express directory bucket")

    base = ctx.unique_name("sim2reallb").rstrip("-").replace("_", "-").lower()
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


def _delete_directory_bucket(s3, bucket: str) -> None:
    try:
        listed = s3.list_objects_v2(Bucket=bucket)
        for obj in listed.get("Contents", []):
            try:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
