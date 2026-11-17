"""gzip-object-etag-and-copy-metadata-directive-content-encoding."""

from __future__ import annotations

import gzip
import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "gzip-object-etag-and-copy-metadata-directive-content-encoding"
GROUP = "data_integrity"
SERVICES = ["s3"]


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; only not-found is tolerated."""
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


def _new_bucket(ctx, s3):
    """Create a uniquely-named bucket and register its teardown."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject's ETag and length pin to the gzip bytes as sent; CopyObject's
    MetadataDirective decides whether Content-Encoding survives unrestated.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    body = gzip.compress(b"a plain text payload compressed before it is stored")
    expected_md5 = hashlib.md5(body).hexdigest()
    src_key = "src.txt.gz"

    put = s3.put_object(
        Bucket=bucket, Key=src_key, Body=body,
        ContentEncoding="gzip", ContentType="text/plain",
    )
    put_etag = put["ETag"].strip('"')
    assert put_etag == expected_md5, (
        f"PutObject ETag {put_etag!r} != MD5 of the {len(body)} compressed bytes {expected_md5!r}"
    )

    head = s3.head_object(Bucket=bucket, Key=src_key)
    assert head["ETag"].strip('"') == expected_md5, (
        f"HeadObject ETag {head['ETag']!r} != MD5 of the compressed bytes {expected_md5!r}"
    )
    assert head["ContentEncoding"] == "gzip", (
        f"HeadObject ContentEncoding {head.get('ContentEncoding')!r}, expected 'gzip'"
    )
    assert head["ContentType"] == "text/plain", (
        f"HeadObject ContentType {head.get('ContentType')!r}, expected 'text/plain'"
    )
    assert head["ContentLength"] == len(body), (
        f"HeadObject ContentLength {head['ContentLength']}, expected {len(body)} "
        f"(the compressed length)"
    )

    got = s3.get_object(Bucket=bucket, Key=src_key)
    assert got["ContentEncoding"] == "gzip", (
        f"GetObject ContentEncoding {got.get('ContentEncoding')!r}, expected 'gzip'"
    )
    assert got["ContentType"] == "text/plain", (
        f"GetObject ContentType {got.get('ContentType')!r}, expected 'text/plain'"
    )
    assert got["ContentLength"] == len(body), (
        f"GetObject ContentLength {got['ContentLength']}, expected {len(body)}"
    )
    raw = got["Body"].read()
    assert raw == body, (
        f"GetObject returned {len(raw)} bytes that differ from the {len(body)} compressed "
        f"bytes written — the target must serve the compressed body verbatim, not decode it"
    )

    source = {"Bucket": bucket, "Key": src_key}

    copy_key = "copy-directive-copy.txt.gz"
    s3.copy_object(Bucket=bucket, Key=copy_key, CopySource=source, MetadataDirective="COPY")
    head_copy = s3.head_object(Bucket=bucket, Key=copy_key)
    assert head_copy.get("ContentEncoding") == "gzip", (
        f"CopyObject MetadataDirective=COPY: HeadObject ContentEncoding "
        f"{head_copy.get('ContentEncoding')!r}, expected 'gzip' to survive the copy"
    )

    replace_key = "copy-directive-replace.txt.gz"
    s3.copy_object(
        Bucket=bucket, Key=replace_key, CopySource=source,
        MetadataDirective="REPLACE", ContentType="text/plain",
    )
    head_replace = s3.head_object(Bucket=bucket, Key=replace_key)
    assert head_replace.get("ContentEncoding") is None, (
        f"CopyObject MetadataDirective=REPLACE without restating ContentEncoding: HeadObject "
        f"ContentEncoding is {head_replace.get('ContentEncoding')!r}, expected it dropped (None)"
    )
    assert head_replace["ContentType"] == "text/plain", (
        f"CopyObject MetadataDirective=REPLACE: HeadObject ContentType "
        f"{head_replace.get('ContentType')!r}, expected the restated 'text/plain'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
