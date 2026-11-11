"""empty-and-odd-sized-objects-under-unicode-keys-round-trip-with-md5-etags."""

from __future__ import annotations

import hashlib
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-and-odd-sized-objects-under-unicode-keys-round-trip-with-md5-etags"
GROUP = 'lifecycle'
SERVICES = ['s3']

NO_SUCH_KEY = ("NoSuchKey", "The specified key does not exist.")
NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it. Tolerates only
    NoSuchBucket (the body already deleted it); any other error raises."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    # us-east-1 is S3's one region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _err(fn):
    """Call fn(); return the ClientError response it raises. An unexpected success raises, so a
    target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _refusal(resp, what, status, exact=False):
    """(code, message) of a refusal, after grading its HTTP status: the class, or the exact
    status (exact=True) only where it is the signal: HEAD, and GET of an object."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    if exact:
        assert got_status == status, f"{what}: expected HTTP {status}, got {got_status!r}"
    else:
        assert isinstance(got_status, int) and got_status // 100 == status // 100, (
            f"{what}: expected HTTP {status // 100}xx, got {got_status!r}"
        )
    return err.get("Code"), err.get("Message")


#: Bounded convergence for a deleted bucket to answer HeadBucket 404; a deadline, never an
#: assertion on elapsed time.
_GONE_S = 40.0


def _poll_head_bucket_gone(s3, bucket):
    """The HeadBucket refusal once the delete converges; a success meanwhile is retried."""
    deadline = time.monotonic() + _GONE_S
    while True:
        try:
            s3.head_bucket(Bucket=bucket)
        except ClientError as exc:
            return exc.response
        if time.monotonic() >= deadline:
            raise AssertionError(f"HeadBucket {bucket}: still answers {_GONE_S:.0f}s after DeleteBucket")
        time.sleep(1.0)


def _quoted_md5(body: bytes) -> str:
    """The ETag of a single-part SSE-S3 object: the quoted hex MD5 of its bytes."""
    return '"' + hashlib.md5(body).hexdigest() + '"'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A zero-byte object and an object of random odd length, under multi-byte UTF-8 keys with
    spaces, each round-trip byte-exact with their own MD5 ETag and size on every read and in the
    listing; once deleted each reads NoSuchKey, and the deleted bucket refuses further writes."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    empty_key = "données/空 ファイル (0).txt"
    odd_key = "données/Ünïcødé — größe.bin"
    odd_len = 2 * secrets.randbelow(40000) + 1001
    objects = {empty_key: b"", odd_key: secrets.token_bytes(odd_len)}

    for key, body in objects.items():
        want = _quoted_md5(body)
        put_etag = s3.put_object(Bucket=bucket, Key=key, Body=body)["ETag"]
        assert put_etag == want, f"PutObject {len(body)} bytes: ETag {put_etag!r} != quoted MD5 {want!r}"
        head = s3.head_object(Bucket=bucket, Key=key)
        assert (head["ETag"], head["ContentLength"]) == (want, len(body)), (
            f"HeadObject {len(body)} bytes: (ETag, ContentLength) {(head['ETag'], head['ContentLength'])!r}"
            f" != {(want, len(body))!r}"
        )
        got = s3.get_object(Bucket=bucket, Key=key)
        data = got["Body"].read()
        assert data == body, f"{len(body)}-byte body did not round-trip byte-exact ({len(data)} bytes back)"
        assert got["ETag"] == want, f"GetObject ETag {got['ETag']!r} != quoted MD5 {want!r}"

    listed = s3.list_objects_v2(Bucket=bucket, Prefix="données/").get("Contents", [])
    got_listing = [(o["Key"], o["Size"], o["ETag"]) for o in listed]
    # ListObjectsV2 returns keys in ascending UTF-8 binary order.
    want_listing = [
        (k, len(objects[k]), _quoted_md5(objects[k])) for k in sorted(objects, key=lambda k: k.encode("utf-8"))
    ]
    assert got_listing == want_listing, f"ListObjectsV2 reports {got_listing!r}, expected {want_listing!r}"

    for key in objects:
        s3.delete_object(Bucket=bucket, Key=key)
        got = _refusal(_err(lambda k=key: s3.get_object(Bucket=bucket, Key=k)), "GetObject after delete", 404, exact=True)
        assert got == NO_SUCH_KEY, f"GetObject after delete: expected {NO_SUCH_KEY}, got {got!r}"
    left = s3.list_objects_v2(Bucket=bucket, Prefix="données/").get("Contents", [])
    assert not left, f"deleted keys still listed by ListObjectsV2: {[o['Key'] for o in left]!r}"

    s3.delete_bucket(Bucket=bucket)
    # A HEAD refusal has no body: the SDK reads the status as the code and its reason as the message.
    got = _refusal(_poll_head_bucket_gone(s3, bucket), "HeadBucket after DeleteBucket", 404, exact=True)
    assert got == ("404", "Not Found"), f"HeadBucket after DeleteBucket: expected ('404', 'Not Found'), got {got!r}"
    got = _refusal(_err(lambda: s3.put_object(Bucket=bucket, Key=empty_key, Body=b"")), "PutObject into deleted bucket", 404)
    assert got == NO_SUCH_BUCKET, f"PutObject into deleted bucket: expected {NO_SUCH_BUCKET}, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
