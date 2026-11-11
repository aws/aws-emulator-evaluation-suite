"""conc-s3-conditional-writes-get-during-overwrite-returns-a-whole-version."""

from __future__ import annotations

import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-get-during-overwrite-returns-a-whole-version"
GROUP = 'concurrency'
SERVICES = ['s3']

_BODY_BYTES = 4 * 1024 * 1024
_OVERWRITES = 6
_READERS = 3


def _delete_bucket(s3, bucket):
    """Abort uploads, empty every version and marker, then delete the bucket (raises if it cannot)."""
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-condw-")
    params = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a region pin.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _md5_etag(body):
    return '"' + hashlib.md5(body).hexdigest() + '"'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GETs that overlap a chain of If-Match overwrites each return one whole known version with its
    own ETag and full length, never a torn or mislabelled body, and the GET after the writer finishes
    returns the last version."""
    s3 = ctx.client("s3")
    pool_client = ctx.client("s3", config=Config(max_pool_connections=(_READERS + 1) * 2))
    # The writer's PUTs are conditional, so a transport retry of one that landed would read 412.
    writer_client = ctx.client("s3", config=Config(retries={"total_max_attempts": 1}))
    bucket = _new_bucket(ctx, s3)
    key = "hot/config-blob.bin"

    versions = [os.urandom(_BODY_BYTES) for _ in range(_OVERWRITES + 1)]
    by_digest = {hashlib.sha256(b).hexdigest(): i for i, b in enumerate(versions)}
    assert len(by_digest) == len(versions), "version bodies are not distinct"
    etag = s3.put_object(Bucket=bucket, Key=key, Body=versions[0])["ETag"]

    done = threading.Event()

    def _writer():
        nonlocal etag
        try:
            for i in range(1, _OVERWRITES + 1):
                etag = writer_client.put_object(Bucket=bucket, Key=key, Body=versions[i],
                                                IfMatch=etag)["ETag"]
        finally:
            done.set()

    def _reader(r):
        seen = []
        while True:
            last_round = done.is_set()
            got = pool_client.get_object(Bucket=bucket, Key=key)
            body = got["Body"].read()
            digest = hashlib.sha256(body).hexdigest()
            assert len(body) == _BODY_BYTES == got["ContentLength"], (
                f"reader {r} got {len(body)} bytes with Content-Length {got['ContentLength']!r}; "
                f"every version is {_BODY_BYTES} bytes: a partial read"
            )
            assert digest in by_digest, (
                f"reader {r} got a body (sha256 {digest}) matching none of the "
                f"{len(versions)} versions ever written: a torn or mixed read"
            )
            assert got["ETag"] == _md5_etag(body), (
                f"reader {r} got version {by_digest[digest]}'s bytes under ETag {got['ETag']!r}; "
                f"that version's ETag is {_md5_etag(body)!r}"
            )
            seen.append(by_digest[digest])
            if last_round:
                return seen

    with ThreadPoolExecutor(max_workers=_READERS + 1) as pool:
        w = pool.submit(_writer)
        readers = [pool.submit(_reader, r) for r in range(_READERS)]
        w.result()
        seen = [f.result() for f in readers]

    for r, s in enumerate(seen):
        assert s, f"reader {r} completed no reads"
        assert s[-1] == _OVERWRITES, (
            f"reader {r}'s read issued after the writer finished saw version {s[-1]}, not the "
            f"last written {_OVERWRITES}: a stale read after a completed overwrite"
        )

    final = s3.get_object(Bucket=bucket, Key=key)
    assert final["Body"].read() == versions[_OVERWRITES], "the final GET is not the last version"
    assert final["ETag"] == etag == _md5_etag(versions[_OVERWRITES]), (
        f"final ETag {final['ETag']!r}, writer's last ETag {etag!r}: want equal and the MD5"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
