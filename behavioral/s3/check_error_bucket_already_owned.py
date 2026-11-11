"""error-bucket-already-owned."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-bucket-already-owned"
GROUP = 'errors'
SERVICES = ['s3']

ERR_BUCKET_ALREADY_OWNED = "BucketAlreadyOwnedByYou"
_ALREADY_OWNED_MESSAGE = "Your previous request to create the named bucket succeeded and you already own it."


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _err(fn, what):
    """Call fn(); return the botocore Error dict it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"{what} succeeded; expected a refusal")


def _creation_date(s3, bucket):
    """list_buckets entry for `bucket`, or None if it is not there — an independent read."""
    for b in s3.list_buckets().get("Buckets", []):
        if b["Name"] == bucket:
            return b.get("CreationDate")
    return None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating an existing bucket you own returns BucketAlreadyOwnedByYou, and the bucket
    itself is untouched by the rejected attempt — not silently deleted and recreated."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    before = _creation_date(s3, bucket)
    assert before is not None, f"bucket {bucket!r} missing from list_buckets right after create"

    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    # On real AWS in us-east-1, re-creating your own bucket succeeds (200).
    # BucketAlreadyOwnedByYou is returned in other regions.
    if ctx.region == "us-east-1":
        try:
            s3.create_bucket(**create_kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            assert err.get("Code") == ERR_BUCKET_ALREADY_OWNED, (
                f"expected success or {ERR_BUCKET_ALREADY_OWNED}, got {err!r}"
            )
            assert err.get("Message") == _ALREADY_OWNED_MESSAGE, err.get("Message")
    else:
        err = _err(lambda: s3.create_bucket(**create_kwargs), "re-creating a bucket this account owns")
        assert err.get("Code") == ERR_BUCKET_ALREADY_OWNED, (
            f"expected {ERR_BUCKET_ALREADY_OWNED}, got {err!r}"
        )
        assert err.get("Message") == _ALREADY_OWNED_MESSAGE, err.get("Message")

    # Independent read at a different operation (list_buckets, not create_bucket): the bucket
    # must still be there. list_buckets' CreationDate is not a stable identity signal (it can
    # differ by a second between calls), so only existence is asserted.
    after = _creation_date(s3, bucket)
    assert after is not None, f"bucket {bucket!r} vanished from list_buckets after the re-create attempt"

    # Restore leg: delete the bucket, then the identical create call must now succeed — proving
    # the rejection was really "you already own this name", not a blanket ban on a second
    # CreateBucket call for this session.
    s3.delete_bucket(Bucket=bucket)
    # HeadBucket answers with no body, so its 404 status is the whole refusal to grade
    gone_code = _err(lambda: s3.head_bucket(Bucket=bucket), "HeadBucket of the deleted bucket").get("Code")
    assert gone_code == "404", f"expected head_bucket 404 after delete, got {gone_code!r}"
    try:
        s3.create_bucket(**create_kwargs)
    except ClientError as exc:
        raise AssertionError(
            f"expected the identical create_bucket to succeed once the bucket was deleted, got {exc.response.get('Error')!r}"
        ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
