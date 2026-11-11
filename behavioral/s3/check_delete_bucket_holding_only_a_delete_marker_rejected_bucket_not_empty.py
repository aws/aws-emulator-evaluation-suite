"""delete-bucket-holding-only-a-delete-marker-rejected-bucket-not-empty."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-bucket-holding-only-a-delete-marker-rejected-bucket-not-empty"
GROUP = 'errors'
SERVICES = ['s3']

# A versioned bucket's refusal names the versions that keep it non-empty.
NOT_EMPTY = (
    "BucketNotEmpty",
    "The bucket you tried to delete is not empty. You must delete all versions in the bucket.",
)
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


def _assert_gone(s3, bucket):
    """HeadBucket answers 404 (bounded), ListBuckets omits it, a PutObject into it is refused."""
    deadline = time.monotonic() + 40
    while True:
        try:
            s3.head_bucket(Bucket=bucket)
        except ClientError as exc:
            head = exc.response
            break
        assert time.monotonic() < deadline, f"bucket {bucket} still answers HeadBucket after DeleteBucket"
        time.sleep(1.0)
    # HEAD responses carry no body, so the code and message come from the bare 404 status.
    assert _code_msg_status(head) == ("404", "Not Found", 404), f"HeadBucket after delete: {_code_msg_status(head)!r}"
    names = [b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])]
    assert bucket not in names, f"deleted bucket still listed by ListBuckets: {names!r}"
    code, msg, status = _code_msg_status(_err(lambda: s3.put_object(Bucket=bucket, Key="x", Body=b"x")))
    assert (code, msg) == NO_SUCH_BUCKET and status == 404, (
        f"PutObject into the deleted bucket: expected {NO_SUCH_BUCKET} HTTP 404, got {(code, msg, status)!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A versioned bucket whose only entry is a delete marker for a never-written key still refuses
    DeleteBucket with BucketNotEmpty and keeps that marker; deleting the marker by its version id is
    exactly what lets the identical DeleteBucket succeed.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/delete-bucket.html
    """
    s3 = ctx.client("s3")

    # Positive control: a versioned bucket that never held anything deletes.
    control = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=control, VersioningConfiguration={"Status": "Enabled"})
    s3.delete_bucket(Bucket=control)
    _assert_gone(s3, control)

    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    key = "never-written/report.csv"
    marker = s3.delete_object(Bucket=bucket, Key=key)
    assert marker.get("DeleteMarker") is True and marker.get("VersionId"), (
        f"DeleteObject on an absent key in a versioned bucket did not create a delete marker: {marker!r}"
    )
    marker_id = marker["VersionId"]
    assert not s3.list_objects_v2(Bucket=bucket).get("Contents"), "the current listing is not empty"

    code, msg, status = _code_msg_status(_err(lambda: s3.delete_bucket(Bucket=bucket)))
    assert (code, msg) == NOT_EMPTY and status == 409, (
        f"DeleteBucket holding one delete marker: expected {NOT_EMPTY} HTTP 409, got {(code, msg, status)!r}"
    )
    s3.head_bucket(Bucket=bucket)
    listed = s3.list_object_versions(Bucket=bucket)
    got = ([(m["Key"], m["VersionId"]) for m in listed.get("DeleteMarkers", [])], listed.get("Versions", []))
    assert got == ([(key, marker_id)], []), f"the refused DeleteBucket changed the version listing: {got!r}"

    s3.delete_object(Bucket=bucket, Key=key, VersionId=marker_id)
    s3.delete_bucket(Bucket=bucket)
    _assert_gone(s3, bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
