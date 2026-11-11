"""rename-object-lifecycle."""

from __future__ import annotations
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "rename-object-lifecycle"
GROUP = 'directory_buckets'
SERVICES = ['s3']

# AWS-assigned physical Availability Zone IDs are stable, non-account-varying identifiers
# (unlike AZ *names*, which are remapped per account) — required verbatim in a directory
# bucket's name, so pinning them per region is a contract, not an environment assumption.
EXPRESS_ZONE_IDS = {
    "us-east-1": "use1-az4",
    "us-east-2": "use2-az1",
    "us-west-2": "usw2-az1",
    "ap-south-1": "aps1-az1",
    "ap-northeast-1": "apne1-az1",
    "eu-central-1": "euc1-az1",
    "eu-west-1": "euw1-az1",
    "eu-north-1": "eun1-az1",
}


def _delete_directory_bucket(client, bucket):
    """Delete every object + abort lingering multipart uploads in a directory bucket, then delete it."""
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []) or []:
                try:
                    client.delete_object(Bucket=bucket, Key=obj["Key"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        resp = client.list_multipart_uploads(Bucket=bucket)
        for u in resp.get("Uploads", []) or []:
            try:
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "NoSuchBucket",
                    "NoSuchKey",
                    "NoSuchUpload",
                ):
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_directory_bucket(ctx, s3):
    """Create an S3 Express One Zone directory bucket (non-ctx Zonal capability), register teardown."""
    zone_id = EXPRESS_ZONE_IDS.get(ctx.region)
    if not zone_id:
        raise AssertionError(f"no known S3 Express One Zone Availability Zone for region {ctx.region!r}")
    name = f"{ctx.unique_name('sim2real-dir-')}--{zone_id}--x-s3"
    try:
        s3.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={
                "Location": {"Type": "AvailabilityZone", "Name": zone_id},
                "Bucket": {"Type": "Directory", "DataRedundancy": "SingleAvailabilityZone"},
            },
        )
    except Exception as exc:
        raise AssertionError(f"directory bucket creation not supported here: {exc}") from exc
    ctx.on_cleanup(lambda: _delete_directory_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RenameObject moves an object in a directory bucket: new key becomes readable, old key
    stops resolving."""
    s3 = ctx.client("s3")
    name = _new_directory_bucket(ctx, s3)
    src, dst = "rename-src.txt", "rename-dst.txt"
    body = b"rename-me"
    s3.put_object(Bucket=name, Key=src, Body=body)

    try:
        s3.rename_object(Bucket=name, Key=dst, RenameSource=src)
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks RenameObject support: {exc}") from exc

    moved = s3.head_object(Bucket=name, Key=dst)
    assert moved["ContentLength"] == len(body), (
        f"renamed object length mismatch: expected {len(body)}, got {moved['ContentLength']}"
    )
    got = s3.get_object(Bucket=name, Key=dst)
    got_body = got["Body"].read()
    assert got_body == body, f"renamed object content mismatch: expected {body!r}, got {got_body!r}"

    gone = _error(lambda: s3.get_object(Bucket=name, Key=src))
    assert gone == ("NoSuchKey", "The specified key does not exist."), (
        f"old key must stop resolving after rename, GetObject gave {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
