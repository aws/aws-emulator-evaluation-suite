"""object-put-get-delete."""

from __future__ import annotations

import hashlib
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "object-put-get-delete"
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


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    # us-east-1 is S3's one region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
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
_GONE_S = 120.0


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Random object bytes round-trip with the MD5 ETag on every read; the deleted object, then the
    deleted bucket, read not-found, are unlisted and refuse further use."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "lifecycle/test-object.bin"
    body = secrets.token_bytes(4096)
    # A single-part PUT under default (SSE-S3) encryption has the quoted hex MD5 of the body as
    # its ETag; every read of the object reports that same ETag.
    expected_etag = '"' + hashlib.md5(body).hexdigest() + '"'
    put_etag = s3.put_object(Bucket=bucket, Key=key, Body=body)["ETag"]
    assert put_etag == expected_etag, f"PutObject ETag {put_etag!r} != quoted MD5 {expected_etag!r}"
    head_etag = s3.head_object(Bucket=bucket, Key=key)["ETag"]
    assert head_etag == expected_etag, f"HeadObject ETag {head_etag!r} != quoted MD5 {expected_etag!r}"
    got_obj = s3.get_object(Bucket=bucket, Key=key)
    got = got_obj["Body"].read()
    assert got == body, f"4 KiB body did not round-trip byte-exact ({len(got)} bytes back)"
    assert got_obj["ETag"] == expected_etag, f"GetObject ETag {got_obj['ETag']!r} != quoted MD5 {expected_etag!r}"
    s3.delete_object(Bucket=bucket, Key=key)
    got = _refusal(_err(lambda: s3.get_object(Bucket=bucket, Key=key)), "GetObject after delete", 404, exact=True)
    assert got == NO_SUCH_KEY, f"GetObject after delete: expected {NO_SUCH_KEY}, got {got!r}"
    listed = s3.list_objects_v2(Bucket=bucket, Prefix=key).get("Contents", [])
    assert not listed, f"deleted key still listed by ListObjectsV2: {[o['Key'] for o in listed]!r}"

    got = _refusal(
        _err(lambda: s3.copy_object(Bucket=bucket, Key="lifecycle/copy-dest.txt", CopySource={"Bucket": bucket, "Key": key})),
        "CopyObject from deleted key", 404,
    )
    assert got == NO_SUCH_KEY, f"CopyObject from deleted key: expected {NO_SUCH_KEY}, got {got!r}"

    reused_body = b"hello-sim2real-reused"
    s3.put_object(Bucket=bucket, Key=key, Body=reused_body)
    head_len = s3.head_object(Bucket=bucket, Key=key)["ContentLength"]
    assert head_len == len(reused_body), f"HeadObject ContentLength {head_len} != {len(reused_body)}"
    got_reused = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got_reused == reused_body, f"key not reusable after delete: {got_reused!r} != {reused_body!r}"

    s3.delete_object(Bucket=bucket, Key=key)
    s3.delete_bucket(Bucket=bucket)
    # Bucket deletion converges: poll HeadBucket (bounded) until it answers 404, then grade it.
    # A HEAD refusal has no body: the SDK reads the status as the code and its reason as the message.
    got = _refusal(_poll_head_bucket_gone(s3, bucket), "HeadBucket after DeleteBucket", 404, exact=True)
    assert got == ("404", "Not Found"), f"HeadBucket after DeleteBucket: expected ('404', 'Not Found'), got {got!r}"
    names = [b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])]
    assert bucket not in names, f"deleted bucket still listed by ListBuckets: {names!r}"
    got = _refusal(_err(lambda: s3.put_object(Bucket=bucket, Key=key, Body=b"x")), "PutObject into deleted bucket", 404)
    assert got == NO_SUCH_BUCKET, f"PutObject into deleted bucket: expected {NO_SUCH_BUCKET}, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
