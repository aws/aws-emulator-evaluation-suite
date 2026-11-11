"""copy-object-and-ranged-get-return-exact-source-bytes-then-batch-delete-removes-both."""

from __future__ import annotations

import hashlib
import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-and-ranged-get-return-exact-source-bytes-then-batch-delete-removes-both"
GROUP = 'lifecycle'
SERVICES = ['s3']

NO_SUCH_KEY = ("NoSuchKey", "The specified key does not exist.")
INVALID_RANGE = ("InvalidRange", "The requested range is not satisfiable")


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


def _refusal(resp, what, status):
    """(code, message) of a refusal, after grading its exact HTTP status."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert got_status == status, f"{what}: expected HTTP {status}, got {got_status!r}"
    return err.get("Code"), err.get("Message")


def _ranged(s3, bucket, key, spec):
    """(HTTP status, Content-Range, ContentLength, bytes) of a ranged GetObject."""
    got = s3.get_object(Bucket=bucket, Key=key, Range=spec)
    return (got["ResponseMetadata"]["HTTPStatusCode"], got.get("ContentRange"), got["ContentLength"],
            got["Body"].read())


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject of a random-length object keeps its MD5 ETag; ranged and suffix-ranged GETs of the
    copy return 206 with exactly the addressed bytes and Content-Range, a range at the size is refused
    416 InvalidRange; DeleteObjects then removes source and copy so both read NoSuchKey."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    src, dst = "copy/source.bin", "copy/nested/destination.bin"
    size = 10000 + secrets.randbelow(20000)
    body = secrets.token_bytes(size)
    etag = '"' + hashlib.md5(body).hexdigest() + '"'

    put_etag = s3.put_object(Bucket=bucket, Key=src, Body=body)["ETag"]
    assert put_etag == etag, f"PutObject ETag {put_etag!r} != quoted MD5 {etag!r}"
    copied = s3.copy_object(Bucket=bucket, Key=dst, CopySource={"Bucket": bucket, "Key": src})
    assert copied["CopyObjectResult"]["ETag"] == etag, (
        f"CopyObject ETag {copied['CopyObjectResult']['ETag']!r} != the source's quoted MD5 {etag!r}"
    )
    got = s3.get_object(Bucket=bucket, Key=dst)
    data = got["Body"].read()
    assert data == body and got["ETag"] == etag, (
        f"GetObject of the copy: {len(data)} bytes, ETag {got['ETag']!r}; expected {size} bytes, {etag!r}"
    )

    start = 1 + secrets.randbelow(size // 2)
    end = start + secrets.randbelow(size - start - 1)
    want = (206, f"bytes {start}-{end}/{size}", end - start + 1, body[start:end + 1])
    assert _ranged(s3, bucket, dst, f"bytes={start}-{end}") == want, (
        f"ranged GET bytes={start}-{end} of the {size}-byte copy did not return exactly that slice"
    )
    tail = 1 + secrets.randbelow(500)
    want = (206, f"bytes {size - tail}-{size - 1}/{size}", tail, body[-tail:])
    assert _ranged(s3, bucket, dst, f"bytes=-{tail}") == want, (
        f"suffix GET bytes=-{tail} of the {size}-byte copy did not return exactly its last {tail} bytes"
    )
    got = _refusal(_err(lambda: s3.get_object(Bucket=bucket, Key=dst, Range=f"bytes={size}-")),
                   "GetObject range at the object size", 416)
    assert got == INVALID_RANGE, f"GetObject bytes={size}-: expected {INVALID_RANGE}, got {got!r}"

    deleted = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": src}, {"Key": dst}]})
    assert sorted(d["Key"] for d in deleted.get("Deleted", [])) == sorted([src, dst]), (
        f"DeleteObjects Deleted {deleted.get('Deleted')!r}, expected both keys"
    )
    assert not deleted.get("Errors"), f"DeleteObjects reported errors {deleted.get('Errors')!r}"
    for key in (src, dst):
        got = _refusal(_err(lambda k=key: s3.get_object(Bucket=bucket, Key=k)), f"GetObject {key} after delete", 404)
        assert got == NO_SUCH_KEY, f"GetObject {key} after DeleteObjects: expected {NO_SUCH_KEY}, got {got!r}"
    left = s3.list_objects_v2(Bucket=bucket, Prefix="copy/").get("Contents", [])
    assert not left, f"keys still listed after DeleteObjects: {[o['Key'] for o in left]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
