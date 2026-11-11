"""put-object-if-match-matches-an-etag-restored-by-rewriting-identical-bytes."""

from __future__ import annotations

import hashlib
import secrets

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-if-match-matches-an-etag-restored-by-rewriting-identical-bytes"
GROUP = 'conditional'
SERVICES = ['s3']

PRECONDITION = ("PreconditionFailed", "At least one of the pre-conditions you specified did not hold", 412)


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; only an already-gone
    bucket is tolerated, every other teardown error raises."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket, register empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    # us-east-1 is S3's one region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _refusal(fn):
    """(Error.Code, Error.Message, HTTP status) of the ClientError ``fn`` raises; FAILS on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"the call SUCCEEDED where real AWS refuses it: {result!r}")


def _md5(body: bytes) -> str:
    return '"' + hashlib.md5(body).hexdigest() + '"'


def _read(s3, bucket, key):
    """(length, MD5 ETag of the bytes, reported ETag) of GetObject, for expected-vs-actual messages."""
    got = s3.get_object(Bucket=bucket, Key=key)
    data = got["Body"].read()
    return data, (len(data), _md5(data), got["ETag"])


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """If-Match compares ETags, not write history: after A, B, then A's bytes again, the first
    write's ETag matches and its PutObject lands, while B's ETag is refused 412 PreconditionFailed
    and the object keeps the bytes of the accepted write.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "documents/ledger.json"
    # One attempt per conditional write: a retried PUT whose first try landed would read as stale.
    once = ctx.client("s3", config=Config(retries={"total_max_attempts": 1}))

    a, b, c = (secrets.token_bytes(64 + secrets.randbelow(64)) for _ in range(3))
    first = s3.put_object(Bucket=bucket, Key=key, Body=a)["ETag"]
    second = s3.put_object(Bucket=bucket, Key=key, Body=b)["ETag"]
    third = s3.put_object(Bucket=bucket, Key=key, Body=a)["ETag"]
    assert (first, second, third) == (_md5(a), _md5(b), _md5(a)), (
        f"PutObject ETags {(first, second, third)!r}, expected the MD5s {(_md5(a), _md5(b), _md5(a))!r}"
    )

    # The first write's ETag is current again, because the current bytes are A's.
    put = once.put_object(Bucket=bucket, Key=key, Body=c, IfMatch=first)
    assert put["ETag"] == _md5(c), f"If-Match PutObject ETag {put['ETag']!r}, expected {_md5(c)!r}"
    data, seen = _read(s3, bucket, key)
    want = (len(c), _md5(c), _md5(c))
    assert data == c and seen == want, f"the accepted If-Match write: read (len, md5, ETag) {seen!r}, expected {want!r}"

    # B's ETag no longer matches: refused, and C survives.
    for stale, label in ((second, "B"), (first, "A")):
        late = _refusal(lambda s=stale: once.put_object(Bucket=bucket, Key=key, Body=b"lost", IfMatch=s))
        assert late == PRECONDITION, f"If-Match on {label}'s ETag: expected {PRECONDITION!r}, got {late!r}"
    head = s3.head_object(Bucket=bucket, Key=key)
    assert (head["ETag"], head["ContentLength"]) == (_md5(c), len(c)), (
        f"after the refusals HeadObject reports {(head['ETag'], head['ContentLength'])!r}, expected "
        f"{(_md5(c), len(c))!r}"
    )
    data, seen = _read(s3, bucket, key)
    assert data == c, f"a refused If-Match write replaced the object: read (len, md5, ETag) {seen!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
