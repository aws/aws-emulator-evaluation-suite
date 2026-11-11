"""get-object-attributes-no-such-key."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "get-object-attributes-no-such-key"
GROUP = 'errors'
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
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes on a missing object raises NoSuchKey; a real object in the
    same bucket still resolves correctly, before and after the forbidden read."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # Positive control: prove the operation works normally before asserting the negative.
    key = "exists.txt"
    body = b"attributes-positive-control"
    put = s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    attrs = s3.get_object_attributes(
        Bucket=bucket, Key=key, ObjectAttributes=["ETag", "StorageClass", "ObjectSize"]
    )
    assert attrs["ObjectSize"] == len(body), f"expected size {len(body)}, got {attrs.get('ObjectSize')}"
    assert attrs["ETag"].strip('"') == put["ETag"].strip('"'), (
        f"ETag mismatch: {attrs['ETag']} vs {put['ETag']}"
    )

    err = _client_error(
        lambda: s3.get_object_attributes(
            Bucket=bucket,
            Key="never-existed.txt",
            ObjectAttributes=["ETag", "StorageClass", "ObjectSize"],
        )
    )
    assert err.get("Code") == "NoSuchKey", f"expected NoSuchKey, got {err!r}"
    assert err.get("Message") == "The specified key does not exist.", err

    # The forbidden read did not disturb the real object's attributes.
    attrs_again = s3.get_object_attributes(Bucket=bucket, Key=key, ObjectAttributes=["ETag"])
    assert attrs_again["ETag"].strip('"') == put["ETag"].strip('"'), (
        "real object's ETag changed after a read of a missing key"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
