"""checksum-crc32."""

from __future__ import annotations

import base64
import zlib

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "checksum-crc32"
GROUP = 'data_integrity'
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


def _crc32_b64(data: bytes) -> str:
    """The base64 big-endian CRC32 of ``data``, in the form S3 puts in ChecksumCRC32."""
    return base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with ChecksumAlgorithm=CRC32 stores the client-computed digest; GET returns that value."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"crc32-test-payload"
    expected = _crc32_b64(body)

    put = s3.put_object(
        Bucket=bucket,
        Key="crc32-obj",
        Body=body,
        ChecksumAlgorithm="CRC32",
    )
    assert put.get("ChecksumCRC32") == expected, (
        f"PutObject echoed ChecksumCRC32={put.get('ChecksumCRC32')!r}; the client computed "
        f"{expected!r} with zlib.crc32 over the same {len(body)} bytes"
    )

    resp = s3.get_object(Bucket=bucket, Key="crc32-obj", ChecksumMode="ENABLED")
    crc = resp.get("ChecksumCRC32")
    assert crc == expected, (
        f"GetObject with ChecksumMode=ENABLED returned ChecksumCRC32={crc!r}; the client "
        f"computed {expected!r} with zlib.crc32 over the same {len(body)} bytes"
    )
    got_body = resp["Body"].read()
    assert got_body == body, f"GetObject returned {len(got_body)} bytes, want {len(body)}"
    assert _crc32_b64(got_body) == crc, (
        f"the bytes S3 returned hash to {_crc32_b64(got_body)!r} but S3 reported "
        f"ChecksumCRC32={crc!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
