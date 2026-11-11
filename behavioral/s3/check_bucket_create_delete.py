"""bucket-create-delete."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-create-delete"
GROUP = 'lifecycle'
SERVICES = ['s3']


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
    """Create a uniquely-named, tagged bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": "true"}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBucket then HeadBucket succeeds (positive control); DeleteBucket removes it, an
    independent HeadBucket then returns the specific not-found code, and a mutation (PutObject)
    against the dead bucket id also fails rather than only the read."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    # Positive control: the bucket exists and is reachable.
    s3.head_bucket(Bucket=bucket)
    # Delete the bucket to exercise the delete path (registered teardown re-attempts, best-effort).
    s3.delete_bucket(Bucket=bucket)
    # Independent read: HeadBucket now returns the specific not-found code, not just "some error".
    # A HEAD response carries no body, so there is no AWS message to compare.
    head_code, _ = _client_error(lambda: s3.head_bucket(Bucket=bucket))
    assert head_code == "404", f"expected 404 on HeadBucket after delete, got {head_code!r}"
    # A mutation against the dead id fails too, not just a read.
    put_code, put_message = _client_error(lambda: s3.put_object(Bucket=bucket, Key="probe", Body=b"x"))
    assert put_code == "NoSuchBucket", f"expected NoSuchBucket on PutObject to deleted bucket, got {put_code!r}"
    expected = "The specified bucket does not exist"
    assert put_message == expected, f"expected message {expected!r}, got {put_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
