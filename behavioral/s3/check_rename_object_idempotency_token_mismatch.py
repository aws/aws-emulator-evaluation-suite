"""rename-object-idempotency-token-mismatch."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rename-object-idempotency-token-mismatch"
GROUP = "concurrency"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RenameObject retried with the same ClientToken but different parameters
    returns IdempotentParameterMismatch instead of silently re-executing; the
    same ClientToken with the SAME parameters is a no-op idempotent success."""
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    ec2 = ctx.client("ec2")

    try:
        azs = ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
        if not azs:
            raise AssertionError("no availability zones found in this region")
        zone_ids = [az["ZoneId"] for az in azs]
    except ClientError as exc:
        raise AssertionError(f"could not resolve availability zone: {_error_code_of(exc)}")

    base = ctx.unique_name("sim2real").replace("_", "-")[:20].strip("-")
    bucket = None
    last_err: ClientError | None = None
    for zone_id in zone_ids:
        candidate = f"{base}--{zone_id}--x-s3"
        try:
            s3.create_bucket(
                Bucket=candidate,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": zone_id},
                    "Bucket": {"Type": "Directory", "DataRedundancy": "SingleAvailabilityZone"},
                },
            )
        except ClientError as exc:
            last_err = exc
            continue
        bucket = candidate
        break
    if bucket is None:
        raise AssertionError(
            f"directory buckets (S3 Express One Zone) unavailable in this account/region "
            f"(tried {len(zone_ids)} zones): {_error_code_of(last_err)}"
        )

    def _cleanup_bucket() -> None:
        try:
            listing = s3.list_objects_v2(Bucket=bucket)
            for obj in listing.get("Contents", []):
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

    ctx.on_cleanup(_cleanup_bucket)

    src_key = "src-object.txt"
    dst_key = "dst-object.txt"
    try:
        s3.put_object(Bucket=bucket, Key=src_key, Body=b"payload-v1")
    except ClientError as exc:
        raise AssertionError(f"could not write to directory bucket: {_error_code_of(exc)}")

    token = "tok-" + ctx.unique_name("rn").replace("_", "")[:20]

    try:
        s3.rename_object(
            Bucket=bucket,
            Key=dst_key,
            RenameSource=src_key,
            ClientToken=token,
        )
    except ClientError as exc:
        raise AssertionError(f"RenameObject not usable in this environment: {_error_code_of(exc)}")

    # confirm the rename actually happened: old key gone, new key present with content
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=src_key)) == "404"
    body = s3.get_object(Bucket=bucket, Key=dst_key)["Body"].read()
    assert body == b"payload-v1"

    # retry with the SAME client token and the SAME parameters: idempotent no-op success
    resp = s3.rename_object(
        Bucket=bucket,
        Key=dst_key,
        RenameSource=src_key,
        ClientToken=token,
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    # retry with the SAME client token but DIFFERENT parameters: mismatch, not a silent second rename
    s3.put_object(Bucket=bucket, Key="other-src.txt", Body=b"payload-v2")
    try:
        s3.rename_object(
            Bucket=bucket,
            Key="other-dst.txt",
            RenameSource="other-src.txt",
            ClientToken=token,
        )
        raise AssertionError("RenameObject reusing the client token with other parameters succeeded")
    except ClientError as exc:
        err = _error_code_of(exc)
        message = exc.response.get("Error", {}).get("Message")
    assert err == "IdempotentParameterMismatch", f"expected IdempotentParameterMismatch, got {err}"
    want = ("Parameters on this idempotent request are inconsistent with parameters used in "
            "previous request(s).")
    assert message == want, f"expected {want!r}, got {message!r}"

    # the forbidden effect did not happen: "other-src.txt" was NOT renamed to "other-dst.txt"
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key="other-dst.txt")) == "404"
    s3.head_object(Bucket=bucket, Key="other-src.txt")  # still present, unchanged


def _error_code(fn) -> str | None:
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return _error_code_of(exc)


def _error_code_of(exc: Any) -> str:
    try:
        code = exc.response["Error"]["Code"]
    except Exception:
        return str(exc)
    # HeadObject/HeadBucket surface as bare HTTP status, normalize for comparisons
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    if code in ("404", "NotFound") or status == 404:
        return "404"
    return code


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
