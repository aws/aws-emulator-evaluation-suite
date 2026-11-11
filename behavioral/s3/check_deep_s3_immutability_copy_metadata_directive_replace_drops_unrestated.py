"""deep-s3-immutability-copy-metadata-directive-replace-drops-unrestated."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-copy-metadata-directive-replace-drops-unrestated"
GROUP = 'copy-directives'
SERVICES = ['s3']

_BODY = b"bytes-that-every-copy-must-carry-unchanged"
_SRC_META = {"owner": "team-a", "stage": "raw"}


def _delete_bucket(client, bucket):
    """Delete every version and marker, then the bucket."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-imm-")
    params = {"Bucket": name}
    # us-east-1 is the one region that rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """MetadataDirective=COPY carries user metadata and system headers and ignores request metadata;
    REPLACE keeps only what the request restates and resets Content-Type; bytes and ETag match.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    src = s3.put_object(
        Bucket=bucket, Key="src.txt", Body=_BODY, ContentType="text/plain",
        CacheControl="max-age=60", ContentDisposition="attachment; filename=src.txt",
        Metadata=_SRC_META,
    )
    src_etag = src["ETag"]

    # --- COPY: everything comes from the source; request metadata is ignored, not merged.
    s3.copy_object(
        Bucket=bucket, Key="copied.txt", CopySource={"Bucket": bucket, "Key": "src.txt"},
        MetadataDirective="COPY", Metadata={"injected": "must-not-appear"},
    )
    h = s3.head_object(Bucket=bucket, Key="copied.txt")
    assert h["Metadata"] == _SRC_META, (
        f"COPY produced user metadata {h['Metadata']!r}; want exactly the source's {_SRC_META!r} "
        "(metadata on a COPY request is ignored)"
    )
    assert (h["ContentType"], h.get("CacheControl"), h.get("ContentDisposition")) == (
        "text/plain", "max-age=60", "attachment; filename=src.txt"
    ), (
        f"COPY carried ContentType/CacheControl/ContentDisposition as "
        f"{(h['ContentType'], h.get('CacheControl'), h.get('ContentDisposition'))!r}"
    )
    assert h["ETag"] == src_etag, f"COPY changed the ETag: {h['ETag']!r} vs source {src_etag!r}"

    # --- REPLACE restating ONE user key and nothing else: all unrestated headers are dropped.
    s3.copy_object(
        Bucket=bucket, Key="replaced.txt", CopySource={"Bucket": bucket, "Key": "src.txt"},
        MetadataDirective="REPLACE", Metadata={"stage": "curated"},
    )
    h = s3.head_object(Bucket=bucket, Key="replaced.txt")
    assert h["Metadata"] == {"stage": "curated"}, (
        f"REPLACE produced user metadata {h['Metadata']!r}; want only the restated "
        "{'stage': 'curated'} — 'owner' was not restated and must be gone"
    )
    assert h["ContentType"] == "binary/octet-stream", (
        f"REPLACE without a ContentType left ContentType {h['ContentType']!r}; S3 resets it to "
        "its default 'binary/octet-stream'"
    )
    assert "CacheControl" not in h and "ContentDisposition" not in h, (
        f"REPLACE kept unrestated system headers: CacheControl={h.get('CacheControl')!r}, "
        f"ContentDisposition={h.get('ContentDisposition')!r}"
    )
    assert h["ETag"] == src_etag, f"REPLACE changed the ETag: {h['ETag']!r} vs {src_etag!r}"

    # --- REPLACE restating system headers: exactly what was restated.
    s3.copy_object(
        Bucket=bucket, Key="retyped.txt", CopySource={"Bucket": bucket, "Key": "src.txt"},
        MetadataDirective="REPLACE", ContentType="application/json", CacheControl="no-store",
    )
    h = s3.head_object(Bucket=bucket, Key="retyped.txt")
    assert (h["ContentType"], h.get("CacheControl"), h["Metadata"]) == (
        "application/json", "no-store", {}
    ), (
        f"REPLACE with restated headers produced "
        f"{(h['ContentType'], h.get('CacheControl'), h['Metadata'])!r}"
    )
    assert "ContentDisposition" not in h, (
        f"REPLACE kept the unrestated ContentDisposition {h.get('ContentDisposition')!r}"
    )

    # --- Every copy carries identical bytes, and the source itself is untouched.
    for key in ("copied.txt", "replaced.txt", "retyped.txt"):
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert body == _BODY, f"{key} holds {body!r}, want the source bytes {_BODY!r}"
    h = s3.head_object(Bucket=bucket, Key="src.txt")
    assert h["Metadata"] == _SRC_META and h["ContentType"] == "text/plain", (
        f"copying mutated the source: metadata {h['Metadata']!r}, ContentType {h['ContentType']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
