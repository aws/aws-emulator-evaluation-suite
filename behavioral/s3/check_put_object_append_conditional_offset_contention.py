"""put-object-append-conditional-offset-contention."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-object-append-conditional-offset-contention"
GROUP = "concurrency"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent append-mode PutObject calls that both target the same stale
    write offset must resolve to exactly one success and one InvalidWriteOffset
    rejection -- never both succeeding (which would silently corrupt/duplicate data)."""
    s3 = ctx.client("s3")
    bucket = _create_directory_bucket_or_skip(ctx)
    key = "append-object"
    initial = b"A" * 4096

    try:
        s3.put_object(Bucket=bucket, Key=key, Body=initial)
        offset_check = s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        raise AssertionError(f"data-plane PutObject on S3 Express directory bucket failed: {exc}")

    offset = offset_check["ContentLength"]
    assert offset == len(initial), (
        f"expected the freshly-written object to be {len(initial)} bytes, "
        f"HeadObject reports {offset}"
    )

    chunk_a = b"B" * 2048
    chunk_b = b"C" * 2048

    def append(body: bytes):
        return s3.put_object(Bucket=bucket, Key=key, Body=body, WriteOffsetBytes=offset)

    results: list[tuple[str, object]] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(append, chunk_a), pool.submit(append, chunk_b)]
        for fut in futures:
            try:
                results.append(("ok", fut.result()))
            except ClientError as exc:
                results.append(("err", _error_code(exc), exc.response.get("Error", {}).get("Message")))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]
    assert len(successes) == 1, f"expected exactly one successful append, got: {results}"
    assert len(failures) == 1, f"expected exactly one rejected append, got: {results}"
    assert failures[0][1] == "InvalidWriteOffset", (
        f"expected InvalidWriteOffset for the losing racer, got {failures[0][1]!r}"
    )
    want = "The write offset value that you specified does not match the current object size."
    message = failures[0][2]
    assert message == want, f"expected {want!r} for the losing racer, got {message!r}"

    final = s3.head_object(Bucket=bucket, Key=key)
    expected_size = offset + len(chunk_a)  # exactly one chunk landed, never both
    assert final["ContentLength"] == expected_size, (
        f"expected final object size {expected_size} (one append applied), "
        f"got {final['ContentLength']} (results={results})"
    )


def _error_code(exc: ClientError) -> str | None:
    try:
        return exc.response["Error"]["Code"]
    except Exception:  # noqa: BLE001
        return None


def _create_directory_bucket_or_skip(ctx) -> str:
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    try:
        zones = ec2.describe_availability_zones(
            Filters=[
                {"Name": "zone-type", "Values": ["availability-zone"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["AvailabilityZones"]
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"cannot enumerate availability zones for S3 Express: {exc}")

    zone_ids = [z["ZoneId"] for z in zones if z.get("ZoneId")]
    if not zone_ids:
        raise AssertionError("no availability zone IDs discoverable in this account/region")

    base = "".join(ch for ch in ctx.unique_name("sim2exp").lower() if ch.isalnum())[:20]
    last_err: Exception | None = None
    for zone_id in zone_ids:
        bucket = f"{base}--{zone_id}--x-s3"
        try:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": zone_id},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            continue
        ctx.on_cleanup(lambda b=bucket: _delete_directory_bucket(ctx, b))
        return bucket

    raise AssertionError(
        "S3 Express One Zone directory buckets are not available in this account/region "
        f"(tried {len(zone_ids)} availability zones); last error: {last_err}"
    )


def _delete_directory_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
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
