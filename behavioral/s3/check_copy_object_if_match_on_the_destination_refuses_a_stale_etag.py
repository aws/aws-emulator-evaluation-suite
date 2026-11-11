"""copy-object-if-match-on-the-destination-refuses-a-stale-etag."""

from __future__ import annotations

import hashlib
import secrets

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-if-match-on-the-destination-refuses-a-stale-etag"
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
    """CopyObject with If-Match on the destination is refused 412 PreconditionFailed when the
    destination's ETag is stale and leaves its bytes untouched; with the current destination ETag
    the copy lands and the destination reads the source's bytes and ETag.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    src, dst = "staging/release.bin", "live/release.bin"
    # One attempt per conditional write: a retried copy whose first try landed would read as stale.
    once = ctx.client("s3", config=Config(retries={"total_max_attempts": 1}))

    source = secrets.token_bytes(2048 + secrets.randbelow(2048))
    old, current = secrets.token_bytes(300), secrets.token_bytes(301)
    assert s3.put_object(Bucket=bucket, Key=src, Body=source)["ETag"] == _md5(source), "source ETag is not its MD5"
    stale = s3.put_object(Bucket=bucket, Key=dst, Body=old)["ETag"]
    live = s3.put_object(Bucket=bucket, Key=dst, Body=current)["ETag"]
    assert (stale, live) == (_md5(old), _md5(current)), f"destination ETags {(stale, live)!r} are not the MD5s"

    late = _refusal(lambda: once.copy_object(Bucket=bucket, Key=dst, CopySource={"Bucket": bucket, "Key": src},
                                             IfMatch=stale))
    assert late == PRECONDITION, f"CopyObject If-Match on a stale destination ETag: expected {PRECONDITION!r}, got {late!r}"
    data, seen = _read(s3, bucket, dst)
    want = (len(current), live, live)
    assert data == current and seen == want, (
        f"after the refused copy the destination reads (len, md5, ETag) {seen!r}, expected {want!r}"
    )

    done = once.copy_object(Bucket=bucket, Key=dst, CopySource={"Bucket": bucket, "Key": src}, IfMatch=live)
    assert done["CopyObjectResult"]["ETag"] == _md5(source), (
        f"CopyObject ETag {done['CopyObjectResult']['ETag']!r}, expected the source MD5 {_md5(source)!r}"
    )
    data, seen = _read(s3, bucket, dst)
    want = (len(source), _md5(source), _md5(source))
    assert data == source and seen == want, (
        f"after the accepted copy the destination reads (len, md5, ETag) {seen!r}, expected the source's {want!r}"
    )
    # The pre-copy ETag is stale now too.
    again = _refusal(lambda: once.copy_object(Bucket=bucket, Key=dst, CopySource={"Bucket": bucket, "Key": src},
                                              IfMatch=live))
    assert again == PRECONDITION, f"CopyObject If-Match on the replaced ETag: expected {PRECONDITION!r}, got {again!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
