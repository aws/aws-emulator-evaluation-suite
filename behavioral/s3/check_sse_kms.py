"""sse-kms."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "sse-kms"
GROUP = 'server_side_encryption'
SERVICES = ['s3']

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _new_kms_key(ctx, kms) -> str:
    """Create a customer-managed symmetric key, schedule its deletion at cleanup, return its ARN."""
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-sse-kms-"),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"},
              {"TagKey": "sim2real:check", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["Arn"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with ServerSideEncryption=aws:kms binds the object to the CMK the request names.
    Both PutObject and a later HeadObject must report aws:kms and the exact key ARN that
    KMS CreateKey returned, so echoing the header without binding the key is caught.
    """
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    bucket = _new_bucket(ctx, s3)

    key_arn = _new_kms_key(ctx, kms)

    put = s3.put_object(
        Bucket=bucket,
        Key="sse-kms.txt",
        Body=b"kms-encrypted",
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=key_arn,
    )
    assert put.get("ServerSideEncryption") == "aws:kms", (
        f"PutObject reported ServerSideEncryption {put.get('ServerSideEncryption')!r}, want "
        "'aws:kms'"
    )
    assert put.get("SSEKMSKeyId") == key_arn, (
        f"PutObject reported SSEKMSKeyId {put.get('SSEKMSKeyId')!r}, want the check's CMK "
        f"{key_arn!r}"
    )

    head = s3.head_object(Bucket=bucket, Key="sse-kms.txt")
    assert head.get("ServerSideEncryption") == "aws:kms", (
        f"HeadObject reported ServerSideEncryption {head.get('ServerSideEncryption')!r}, want "
        "'aws:kms'"
    )
    assert head.get("SSEKMSKeyId") == key_arn, (
        f"HeadObject reported SSEKMSKeyId {head.get('SSEKMSKeyId')!r}, want the check's CMK "
        f"{key_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
