"""get-object-nonexistent-version-errors."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "get-object-nonexistent-version-errors"
GROUP = 'versioning'
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
    """Call fn(); return the botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject distinguishes a malformed VersionId (InvalidArgument) from a well-formed but no-longer-existing one (NoSuchVersion)."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    v1 = s3.put_object(Bucket=bucket, Key="k", Body=b"v1")["VersionId"]
    v2 = s3.put_object(Bucket=bucket, Key="k", Body=b"v2")["VersionId"]

    # A structurally invalid version id is rejected as a bad argument, NOT as a 404.
    malformed = v1[:-1] + ("A" if v1[-1] != "A" else "B")
    err = _client_error(lambda: s3.get_object(Bucket=bucket, Key="k", VersionId=malformed))
    assert err.get("Code") == "InvalidArgument", f"expected InvalidArgument for a malformed VersionId, got {err!r}"
    assert err.get("Message") == "Invalid version id specified", err

    # Permanently remove v1, then that (well-formed, previously valid) id is NoSuchVersion.
    s3.delete_object(Bucket=bucket, Key="k", VersionId=v1)
    err = _client_error(lambda: s3.get_object(Bucket=bucket, Key="k", VersionId=v1))
    assert err.get("Code") == "NoSuchVersion", f"expected NoSuchVersion for a permanently deleted version, got {err!r}"
    assert err.get("Message") == "The specified version does not exist.", err

    # the surviving version is untouched, and this is the positive control: it proves GetObject
    # with a well-formed, existing VersionId works at all, so the two rejections above are specific
    # to the malformed/deleted input rather than the target refusing every versioned read.
    body = s3.get_object(Bucket=bucket, Key="k", VersionId=v2)["Body"].read()
    assert body == b"v2", f"expected surviving version v2 body b'v2', got {body!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
