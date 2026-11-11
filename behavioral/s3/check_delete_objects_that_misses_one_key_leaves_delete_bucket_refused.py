"""delete-objects-that-misses-one-key-leaves-delete-bucket-refused."""

from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-objects-that-misses-one-key-leaves-delete-bucket-refused"
GROUP = 'errors'
SERVICES = ['s3']

NOT_EMPTY = ("BucketNotEmpty", "The bucket you tried to delete is not empty")
NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; only an already-gone
    bucket (NoSuchBucket) is tolerated."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":  # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _err(fn):
    """Call fn(); return the ClientError response it raises. Raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected a ClientError, the call unexpectedly succeeded: {result!r}")


def _code_msg_status(resp):
    """(Error.Code, Error.Message, HTTP status) of a ClientError response."""
    err = resp.get("Error", {})
    return err.get("Code"), err.get("Message"), resp.get("ResponseMetadata", {}).get("HTTPStatusCode")


def _keys(s3, bucket):
    return [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A DeleteObjects batch that names every key but one empties nothing else away: DeleteBucket
    is still refused BucketNotEmpty and the one survivor reads back its bytes; deleting that last
    key is exactly what lets the identical DeleteBucket succeed."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    count = 3 + secrets.randbelow(4)
    bodies = {f"batch/{i:02d}-{secrets.token_hex(3)}.dat": secrets.token_bytes(16 + i) for i in range(count)}
    for key, body in bodies.items():
        s3.put_object(Bucket=bucket, Key=key, Body=body)
    survivor = sorted(bodies)[secrets.randbelow(count)]
    batch = [k for k in sorted(bodies) if k != survivor]

    resp = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": k} for k in batch]})
    assert sorted(d["Key"] for d in resp.get("Deleted", [])) == batch and not resp.get("Errors"), (
        f"DeleteObjects of {len(batch)} keys reported Deleted {resp.get('Deleted')!r} Errors {resp.get('Errors')!r}"
    )
    assert _keys(s3, bucket) == [survivor], f"after the batch the bucket lists {_keys(s3, bucket)!r}"

    code, msg, status = _code_msg_status(_err(lambda: s3.delete_bucket(Bucket=bucket)))
    assert (code, msg) == NOT_EMPTY and status == 409, (
        f"DeleteBucket with one key left: expected {NOT_EMPTY} HTTP 409, got {(code, msg, status)!r}"
    )
    kept = s3.get_object(Bucket=bucket, Key=survivor)["Body"].read()
    assert kept == bodies[survivor], "the survivor's bytes changed across the refused DeleteBucket"

    resp = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": survivor}]})
    assert [d["Key"] for d in resp.get("Deleted", [])] == [survivor], f"DeleteObjects of the survivor: {resp!r}"
    s3.delete_bucket(Bucket=bucket)
    deadline = time.monotonic() + 40
    while True:
        try:
            s3.head_bucket(Bucket=bucket)
        except ClientError as exc:
            head = exc.response
            break
        assert time.monotonic() < deadline, "the deleted bucket still answers HeadBucket"
        time.sleep(1.0)
    assert _code_msg_status(head) == ("404", "Not Found", 404), f"HeadBucket after delete: {_code_msg_status(head)!r}"
    code, msg, status = _code_msg_status(_err(lambda: s3.put_object(Bucket=bucket, Key=survivor, Body=b"x")))
    assert (code, msg) == NO_SUCH_BUCKET and status == 404, (
        f"PutObject into the deleted bucket: expected {NO_SUCH_BUCKET} HTTP 404, got {(code, msg, status)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
