"""create-session-token-ttl."""

from __future__ import annotations
import datetime
from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "create-session-token-ttl"
GROUP = 'directory_buckets'
SERVICES = ['s3']

# S3 Express One Zone Availability-Zone ids keyed by region (directory buckets are Zonal).
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateSession returns temporary credentials with a fixed ~5-minute TTL (Expiration ~5
    minutes from issuance) and mints an independent session per call; the directory bucket is
    genuinely usable for session-authorized Zonal data-plane calls right after minting."""
    s3 = ctx.client("s3")
    bucket = _new_directory_bucket(ctx, s3)
    key = "session-ttl-obj.txt"

    try:
        session = s3.create_session(Bucket=bucket)
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks CreateSession support: {exc}") from exc
    creds = session["Credentials"]
    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"):
        assert field in creds, f"expected {field!r} in CreateSession Credentials, got {creds.keys()}"

    issued_at = datetime.datetime.now(datetime.timezone.utc)
    ttl = (creds["Expiration"] - issued_at).total_seconds()
    assert 4 * 60 <= ttl <= 6 * 60, f"expected a fixed ~5-minute TTL, got {ttl}s"

    # A second CreateSession call must mint an independent session (its own AccessKeyId/Expiration).
    session2 = s3.create_session(Bucket=bucket)
    creds2 = session2["Credentials"]
    assert creds2["AccessKeyId"] != creds["AccessKeyId"], (
        "each CreateSession call must mint a distinct temporary-credential session"
    )

    # Confirm the bucket is genuinely usable for session-authorized Zonal data-plane calls right
    # after minting (via the same client, which botocore backs with its internal S3Express cache).
    s3.put_object(Bucket=bucket, Key=key, Body=b"session-ttl-payload")
    got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got == b"session-ttl-payload", f"expected round-tripped payload, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
