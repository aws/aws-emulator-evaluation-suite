"""objects-totalling-over-128-mib-across-three-buckets-all-read-back."""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "objects-totalling-over-128-mib-across-three-buckets-all-read-back"
GROUP = "lifecycle"
SERVICES = ["s3"]

_MIB = 1024 * 1024
_OBJECT_SIZE = 15 * _MIB
_BUCKETS = 3
_KEYS = ("part-a.bin", "part-b.bin", "part-c.bin")


def _delete_bucket(s3, bucket: str) -> None:
    """Delete every object, then the bucket; tolerates only not-found."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _put(s3, bucket: str, key: str) -> tuple[str, str]:
    """PutObject a fresh random body; (body MD5, returned ETag)."""
    body = os.urandom(_OBJECT_SIZE)
    etag = s3.put_object(Bucket=bucket, Key=key, Body=body)["ETag"].strip('"')
    return hashlib.md5(body).hexdigest(), etag


def _read_md5(s3, bucket: str, key: str) -> tuple[int, str]:
    """(length, MD5) of the object as GetObject streams it back."""
    digest = hashlib.md5()
    length = 0
    stream = s3.get_object(Bucket=bucket, Key=key)["Body"]
    for chunk in iter(lambda: stream.read(_MIB), b""):
        digest.update(chunk)
        length += len(chunk)
    return length, digest.hexdigest()


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """One account stores nine 15 MiB objects over three buckets, more than 128 MiB in all.

    Every PutObject succeeds with the body's MD5 as ETag and every object reads back byte-exact.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingObjects.html
    """
    s3 = ctx.client("s3")
    buckets = [ctx.unique_name(f"sim2real-behav-vol{i}-") for i in range(_BUCKETS)]
    for bucket in buckets:
        ctx.on_cleanup(lambda b=bucket: _delete_bucket(s3, b))
    location = {}
    # us-east-1 is the one region whose CreateBucket takes no LocationConstraint.
    if ctx.region != "us-east-1":
        location["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    for bucket in buckets:
        s3.create_bucket(Bucket=bucket, **location)

    objects = [(b, k) for b in buckets for k in _KEYS]
    with ThreadPoolExecutor(max_workers=len(_KEYS)) as pool:
        puts = {o: pool.submit(_put, s3, *o) for o in objects}
        sums = {o: f.result() for o, f in puts.items()}
    bad = {o: s for o, s in sums.items() if s[0] != s[1]}
    assert not bad, f"PutObject ETags differ from the bodies' MD5s (MD5, ETag): {bad!r}"

    with ThreadPoolExecutor(max_workers=len(_KEYS)) as pool:
        reads = {o: pool.submit(_read_md5, s3, *o) for o in objects}
        got = {o: f.result() for o, f in reads.items()}
    want = {o: (_OBJECT_SIZE, s[0]) for o, s in sums.items()}
    assert got == want, f"objects read back as (length, MD5) {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
