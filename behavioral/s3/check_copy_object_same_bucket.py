"""copy-object-same-bucket."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "copy-object-same-bucket"
GROUP = 'copy'
SERVICES = ['s3']

_HEAD_ABSENT = ("404", 'Not Found')

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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject within the same bucket produces a byte-identical, independent copy."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"copy-source-data"
    s3.put_object(Bucket=bucket, Key="src.txt", Body=body)
    s3.copy_object(
        Bucket=bucket,
        Key="dst.txt",
        CopySource={"Bucket": bucket, "Key": "src.txt"},
    )
    got = s3.get_object(Bucket=bucket, Key="dst.txt")["Body"].read()
    assert got == body, f"copy destination bytes {got!r} did not match source bytes {body!r}"

    # the copy must be independent of the source: deleting dst.txt must not touch src.txt,
    # and dst.txt itself must actually be gone (not aliased back to src.txt)
    s3.delete_object(Bucket=bucket, Key="dst.txt")
    try:
        s3.head_object(Bucket=bucket, Key="dst.txt")
        raise AssertionError("dst.txt was still readable after delete_object")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == _HEAD_ABSENT, f"expected {_HEAD_ABSENT!r} for deleted dst.txt, got {got!r}"
    still_there = s3.get_object(Bucket=bucket, Key="src.txt")["Body"].read()
    assert still_there == body, (
        f"deleting the copy destination changed the source object: expected {body!r}, got {still_there!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
