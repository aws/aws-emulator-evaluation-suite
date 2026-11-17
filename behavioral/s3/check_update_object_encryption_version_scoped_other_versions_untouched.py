"""update-object-encryption-version-scoped-other-versions-untouched."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-object-encryption-version-scoped-other-versions-untouched"
GROUP = "server-side-encryption"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateObjectEncryption with a VersionId re-encrypts only that version to SSE-KMS, in place:
    bytes and the version list are unchanged, and the bucket's other version of the same key keeps
    its original encryption."""
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    bucket = _new_bucket(ctx, s3)
    key = "versioned-object.bin"

    body_v1 = b"version-one-payload" * 16
    body_v2 = b"version-two-payload" * 16
    version_id_1 = s3.put_object(Bucket=bucket, Key=key, Body=body_v1)["VersionId"]
    version_id_2 = s3.put_object(Bucket=bucket, Key=key, Body=body_v2)["VersionId"]
    assert version_id_1 != version_id_2, (
        f"two puts to the same key on a versioned bucket must mint distinct version ids, got "
        f"{version_id_1!r} twice"
    )

    baseline_v2 = s3.head_object(Bucket=bucket, Key=key, VersionId=version_id_2)
    baseline_v2_sse = baseline_v2.get("ServerSideEncryption")

    kms_key_arn = kms.create_key(
        Description="sim2real-behav update-object-encryption-version-scoped-other-versions-untouched"
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(_teardown(
        lambda: kms.schedule_key_deletion(KeyId=kms_key_arn, PendingWindowInDays=7),
        "NotFoundException",
    ))

    s3.update_object_encryption(
        Bucket=bucket, Key=key, VersionId=version_id_1,
        ObjectEncryption={"SSEKMS": {"KMSKeyArn": kms_key_arn}},
    )

    head_v1 = s3.head_object(Bucket=bucket, Key=key, VersionId=version_id_1)
    assert head_v1.get("ServerSideEncryption") == "aws:kms", (
        f"expected version {version_id_1!r} to carry SSE-KMS after the targeted update, got "
        f"{head_v1.get('ServerSideEncryption')!r}"
    )
    assert head_v1.get("SSEKMSKeyId") == kms_key_arn, (
        f"expected version {version_id_1!r}'s SSEKMSKeyId to be {kms_key_arn!r}, got "
        f"{head_v1.get('SSEKMSKeyId')!r}"
    )

    head_v2 = s3.head_object(Bucket=bucket, Key=key, VersionId=version_id_2)
    assert head_v2.get("ServerSideEncryption") == baseline_v2_sse, (
        f"updating version {version_id_1!r}'s encryption must not touch version {version_id_2!r}: "
        f"expected ServerSideEncryption to stay {baseline_v2_sse!r}, got "
        f"{head_v2.get('ServerSideEncryption')!r}"
    )
    assert "SSEKMSKeyId" not in head_v2, (
        f"version {version_id_2!r} must not have gained an SSEKMSKeyId, got "
        f"{head_v2.get('SSEKMSKeyId')!r}"
    )

    read_back = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id_1)["Body"].read()
    assert read_back == body_v1, (
        f"re-encrypting version {version_id_1!r} must not change its {len(body_v1)}-byte content; "
        f"read back {len(read_back)} byte(s)"
    )

    versions = s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key)
    by_id = {}
    for page in versions:
        for v in page.get("Versions", []):
            if v["Key"] == key:
                by_id[v["VersionId"]] = v
    assert set(by_id) == {version_id_1, version_id_2}, (
        f"expected exactly the two versions {{{version_id_1!r}, {version_id_2!r}}} for {key!r}, "
        f"got {sorted(by_id)!r}"
    )
    assert by_id[version_id_2]["IsLatest"] is True, (
        f"version {version_id_2!r} must remain the latest version, got "
        f"IsLatest={by_id[version_id_2]['IsLatest']!r}"
    )
    assert by_id[version_id_1]["IsLatest"] is False, (
        f"re-encrypting the older version {version_id_1!r} must not promote it to latest, got "
        f"IsLatest={by_id[version_id_1]['IsLatest']!r}"
    )


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named versioned bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-uoe-")
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
