"""copy-object-to-itself-no-change-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "copy-object-to-itself-no-change-rejected"
GROUP = 'copy'
SERVICES = ['s3']

_SELF_COPY_REFUSED = (
    "InvalidRequest",
    "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
)

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
        # us-east-1 literal: S3's CreateBucket rejects an explicit LocationConstraint
        # for that region (its own legacy default) — not a region pin on the check.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A call that SUCCEEDS
    fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Copying an object onto itself with MetadataDirective=COPY is a no-op request and must be rejected with InvalidRequest."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "self-copy.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload", ContentType="text/plain")

    refusal = _error(lambda: s3.copy_object(
        Bucket=bucket, Key=key, CopySource={"Bucket": bucket, "Key": key},
        MetadataDirective="COPY",
    ))
    assert refusal == _SELF_COPY_REFUSED, (
        f"expected {_SELF_COPY_REFUSED!r} for a self-copy with no change, got {refusal!r}"
    )

    # the same self-copy IS legal when metadata actually changes
    s3.copy_object(
        Bucket=bucket, Key=key, CopySource={"Bucket": bucket, "Key": key},
        MetadataDirective="REPLACE", ContentType="application/json",
    )
    replaced_type = s3.head_object(Bucket=bucket, Key=key)["ContentType"]
    assert replaced_type == "application/json", (
        f"expected the metadata-changing self-copy to take effect, got ContentType={replaced_type!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
