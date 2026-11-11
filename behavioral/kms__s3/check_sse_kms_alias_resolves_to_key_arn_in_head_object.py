"""sse-kms-alias-resolves-to-key-arn-in-head-object."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sse-kms-alias-resolves-to-key-arn-in-head-object"
GROUP = "server-side-encryption"
SERVICES = ["kms", "s3"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An SSEKMSKeyId given as a KMS alias is reported by PutObject and HeadObject as the aliased
    key's ARN (per DescribeKey), and a bucket default naming the alias resolves to the same ARN.
    """
    kms = ctx.client("kms")
    s3 = ctx.client("s3")

    key_arn = _new_cmk(ctx, kms)
    alias_name = ctx.unique_name("sim2real-behav-ssekms-")
    kms.create_alias(AliasName=f"alias/{alias_name}", TargetKeyId=key_arn)
    ctx.on_cleanup(lambda: kms.delete_alias(AliasName=f"alias/{alias_name}"))

    # A just-created alias can briefly 404 on DescribeKey/PutObject before it propagates; retry
    # through that window rather than treating the first NotFoundException as the real answer.
    resolved = _poll_until(
        lambda: _describe_key_or_none(kms, f"alias/{alias_name}"),
        lambda arn: arn is not None,
        timeout_s=30,
        description=f"alias/{alias_name} to resolve via DescribeKey",
    )
    assert resolved == key_arn, (
        f"KMS's own DescribeKey on the alias must resolve to the CMK we just made; got "
        f"{resolved!r}, expected {key_arn!r}"
    )

    bucket = _new_bucket(ctx, s3)

    put = s3.put_object(
        Bucket=bucket,
        Key="explicit.txt",
        Body=b"explicit-sse-kms-alias",
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=f"alias/{alias_name}",
    )
    assert put.get("SSEKMSKeyId") == key_arn, (
        f"PutObject's own response must report the ALIAS RESOLVED TO ITS KEY ARN, got "
        f"{put.get('SSEKMSKeyId')!r}, expected {key_arn!r}"
    )

    head = s3.head_object(Bucket=bucket, Key="explicit.txt")
    assert head.get("ServerSideEncryption") == "aws:kms", (
        f"HeadObject must report ServerSideEncryption 'aws:kms', got "
        f"{head.get('ServerSideEncryption')!r}"
    )
    assert head.get("SSEKMSKeyId") == key_arn, (
        f"a later, independent HeadObject must resolve the SAME alias to the SAME key ARN, got "
        f"{head.get('SSEKMSKeyId')!r}, expected {key_arn!r}"
    )

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": f"alias/{alias_name}",
                    },
                    "BucketKeyEnabled": False,
                }
            ]
        },
    )
    enc = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    assert len(enc) == 1, f"expected exactly one default-encryption rule, got {enc!r}"

    default_put = s3.put_object(Bucket=bucket, Key="default.txt", Body=b"bucket-default-sse-kms")
    assert default_put.get("ServerSideEncryption") == "aws:kms", (
        f"an object written with no SSE parameters must inherit the bucket default, got "
        f"ServerSideEncryption={default_put.get('ServerSideEncryption')!r}"
    )
    assert default_put.get("SSEKMSKeyId") == key_arn, (
        f"the bucket-default path must resolve the SAME alias to the SAME key ARN as the "
        f"explicit path, got {default_put.get('SSEKMSKeyId')!r}, expected {key_arn!r}"
    )

    default_head = s3.head_object(Bucket=bucket, Key="default.txt")
    assert default_head.get("SSEKMSKeyId") == key_arn, (
        f"HeadObject on the bucket-default object must resolve to the identical key ARN, got "
        f"{default_head.get('SSEKMSKeyId')!r}, expected {key_arn!r}"
    )

    got = s3.get_object(Bucket=bucket, Key="explicit.txt")["Body"].read()
    assert got == b"explicit-sse-kms-alias", (
        f"GetObject must return the exact bytes written through the alias-keyed SSE-KMS path, "
        f"got {got!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_key_or_none(kms, key_id: str) -> str | None:
    try:
        return kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return None
        raise


def _new_cmk(ctx, kms) -> str:
    """A fresh symmetric CMK; schedules its 7-day deletion (the AWS minimum window)."""
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-ssekms-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _new_bucket(ctx, s3) -> str:
    """A private bucket in ctx.region, emptied (objects + versions) then deleted at teardown."""
    name = ctx.unique_name("sim2real-behav-ssekms-")
    create_kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
