"""rename-object-concurrent-idempotency."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rename-object-concurrent-idempotency"
GROUP = "concurrency"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent RenameObject calls sharing a ClientToken rename the object once: a racer that
    does not succeed gets NoSuchKey with the exact message, and the same token with other
    parameters is refused with IdempotentParameterMismatch."""
    s3 = ctx.client("s3")
    bucket = _create_directory_bucket_or_skip(ctx)
    src_key = "rename-src"
    dst_key = "rename-dst"
    payload = b"payload-for-idempotent-rename"

    try:
        s3.put_object(Bucket=bucket, Key=src_key, Body=payload)
    except ClientError as exc:
        raise AssertionError(f"data-plane PutObject on S3 Express directory bucket failed: {exc}") from exc

    token = ctx.unique_name("tok-")[:64]

    def do_rename():
        return s3.rename_object(Bucket=bucket, Key=dst_key, RenameSource=src_key, ClientToken=token)

    results: list[tuple[str, object]] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(do_rename) for _ in range(2)]
        for fut in futures:
            try:
                results.append(("ok", fut.result()))
            except ClientError as exc:
                results.append(("err", (_error_code(exc), exc.response["Error"].get("Message"))))

    oks = [r for r in results if r[0] == "ok"]
    errs = [r[1] for r in results if r[0] == "err"]
    # A racer that runs after the winner finds the source gone or replays the token's result.
    assert oks, f"expected at least one RenameObject racer to succeed, got: {results}"
    assert all(err == ("NoSuchKey", "The specified key does not exist.") for err in errs), (
        f"a losing racer must fail only with NoSuchKey and its exact message, got {errs}"
    )

    # Convergence: exactly one rename took effect -- destination present, source gone.
    dst_head = s3.head_object(Bucket=bucket, Key=dst_key)
    assert dst_head["ContentLength"] == len(payload)
    src_error = None
    try:
        s3.head_object(Bucket=bucket, Key=src_key)
    except ClientError as exc:
        src_error = (_error_code(exc), exc.response["Error"].get("Message"))
    assert src_error == ("404", "Not Found"), (
        f"expected rename source to be gone after rename, got head_object error {src_error!r}"
    )

    # Reusing the SAME client token with DIFFERENT parameters must be rejected, not
    # silently treated as a fresh rename.
    other_src = "rename-src-2"
    s3.put_object(Bucket=bucket, Key=other_src, Body=b"other-payload")
    mismatch_code = None
    try:
        s3.rename_object(Bucket=bucket, Key="rename-dst-2", RenameSource=other_src, ClientToken=token)
    except ClientError as exc:
        mismatch_code = _error_code(exc)
    assert mismatch_code == "IdempotentParameterMismatch", (
        f"expected IdempotentParameterMismatch on token reuse with different params, "
        f"got {mismatch_code!r}"
    )
    # The mismatched retry must not have performed a second rename.
    other_still_present = False
    try:
        s3.head_object(Bucket=bucket, Key=other_src)
        other_still_present = True
    except ClientError:
        pass
    assert other_still_present, "IdempotentParameterMismatch must not perform the rename"


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
        raise AssertionError(f"cannot enumerate availability zones for S3 Express: {exc}") from exc

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
