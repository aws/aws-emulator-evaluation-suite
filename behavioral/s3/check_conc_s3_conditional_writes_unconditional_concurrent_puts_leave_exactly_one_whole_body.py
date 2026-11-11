"""conc-s3-conditional-writes-unconditional-concurrent-puts-leave-exactly-one-whole-body."""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-unconditional-concurrent-puts-leave-exactly-one-whole-body"
GROUP = 'concurrency'
SERVICES = ['s3']

_WRITERS = 8
_BODY_BYTES = 2 * 1024 * 1024


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
    """Concurrent unconditional PUTs of distinct random bodies to one key leave exactly one whole
    body, with GET, HEAD and ListObjectsV2 metadata matching that writer (any writer may win).
    """
    s3 = ctx.client("s3")
    # Default retries stay on: re-sending an unconditional PUT of the same body is harmless.
    writer_client = ctx.client("s3", config=Config(max_pool_connections=_WRITERS * 2))
    bucket = _new_bucket(ctx, s3)
    key = "contended/last-writer-wins.bin"

    bodies = [os.urandom(_BODY_BYTES) for _ in range(_WRITERS)]
    assert len({hashlib.sha256(b).digest() for b in bodies}) == _WRITERS, "bodies not distinct"
    digest_to_writer = {hashlib.sha256(b).hexdigest(): i for i, b in enumerate(bodies)}

    def _write(i):
        return writer_client.put_object(Bucket=bucket, Key=key, Body=bodies[i])["ETag"]

    with ThreadPoolExecutor(max_workers=_WRITERS) as pool:
        put_etags = list(pool.map(_write, range(_WRITERS)))

    for i, etag in enumerate(put_etags):
        assert etag == _md5_etag(bodies[i]), (
            f"writer {i}'s PUT returned ETag {etag!r}, not the MD5 of its own body "
            f"{_md5_etag(bodies[i])!r}"
        )

    got = s3.get_object(Bucket=bucket, Key=key)
    body = got["Body"].read()
    digest = hashlib.sha256(body).hexdigest()
    assert len(body) == _BODY_BYTES, (
        f"the surviving object is {len(body)} bytes; want {_BODY_BYTES} (truncated or padded)"
    )
    assert digest in digest_to_writer, (
        f"the surviving object (sha256 {digest}) is none of the {_WRITERS} bodies written: a "
        "mixture of concurrent writes"
    )
    winner = digest_to_writer[digest]
    assert got["ETag"] == put_etags[winner] == _md5_etag(body), (
        f"GET ETag {got['ETag']!r} vs writer {winner}'s PUT ETag {put_etags[winner]!r} vs body MD5 "
        f"{_md5_etag(body)!r}: the metadata belongs to a different write than the bytes"
    )

    head = s3.head_object(Bucket=bucket, Key=key)
    assert (head["ETag"], head["ContentLength"]) == (got["ETag"], _BODY_BYTES), (
        f"HeadObject reports {(head['ETag'], head['ContentLength'])!r}; GET reported "
        f"{(got['ETag'], _BODY_BYTES)!r}"
    )
    listed = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed += [(o["Key"], o["ETag"], o["Size"]) for o in page.get("Contents", [])]
    assert listed == [(key, got["ETag"], _BODY_BYTES)], (
        f"ListObjectsV2 reports {listed!r}; want exactly one entry matching the survivor"
    )

    again = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert again == body, "a second GET returned different bytes after all writers had finished"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
