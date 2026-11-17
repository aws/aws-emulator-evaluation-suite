"""update-object-encryption-deleted-version-rejected."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-object-encryption-deleted-version-rejected"
GROUP = "server-side-encryption"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateObjectEncryption on a well-formed VersionId that was permanently deleted fails with
    NoSuchKey, and an untouched, still-current version of the same key can still be re-encrypted
    to SSE-KMS."""
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    bucket = _new_bucket(ctx, s3)
    key = "versioned-object.bin"

    version_id_1 = s3.put_object(Bucket=bucket, Key=key, Body=b"version-one")["VersionId"]
    version_id_2 = s3.put_object(Bucket=bucket, Key=key, Body=b"version-two")["VersionId"]
    s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id_1)

    kms_key_arn = kms.create_key(
        Description="sim2real-behav update-object-encryption-deleted-version-rejected"
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(_teardown(
        lambda: kms.schedule_key_deletion(KeyId=kms_key_arn, PendingWindowInDays=7),
        "NotFoundException",
    ))

    code, message = _error(
        lambda: s3.update_object_encryption(
            Bucket=bucket, Key=key, VersionId=version_id_1,
            ObjectEncryption={"SSEKMS": {"KMSKeyArn": kms_key_arn}},
        )
    )
    assert code == "NoSuchKey", (
        f"expected NoSuchKey for a permanently deleted version id, got {code!r}: {message!r}"
    )
    assert message == "The specified key does not exist.", (
        f"unexpected NoSuchKey message for a permanently deleted version id: {message!r}"
    )

    s3.update_object_encryption(
        Bucket=bucket, Key=key, VersionId=version_id_2,
        ObjectEncryption={"SSEKMS": {"KMSKeyArn": kms_key_arn}},
    )
    head_v2 = s3.head_object(Bucket=bucket, Key=key, VersionId=version_id_2)
    assert head_v2.get("ServerSideEncryption") == "aws:kms", (
        f"a still-current version must still accept UpdateObjectEncryption after the deleted "
        f"version was rejected; got ServerSideEncryption={head_v2.get('ServerSideEncryption')!r}"
    )
    assert head_v2.get("SSEKMSKeyId") == kms_key_arn, (
        f"expected version {version_id_2!r}'s SSEKMSKeyId to be {kms_key_arn!r}, got "
        f"{head_v2.get('SSEKMSKeyId')!r}"
    )


def _error(fn):
    """Call ``fn``, returning its ``(code, message)``; raises if it unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected a ClientError, the call succeeded")


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named versioned bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-uoedv-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: _delete_bucket(s3, name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


def _delete_bucket(client, bucket):
    """Delete every version and marker, then the bucket itself."""
    for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
            client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    client.delete_bucket(Bucket=bucket)


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
