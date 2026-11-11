"""versioning-produces-version-ids."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "versioning-produces-version-ids"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With versioning enabled, PutObject returns distinct VersionIds that are independently
    resolvable to the exact bytes each put wrote."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "ver-key"
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    r1 = s3.put_object(Bucket=bucket, Key=key, Body=b"version-1")
    r2 = s3.put_object(Bucket=bucket, Key=key, Body=b"version-2")
    v1 = r1.get("VersionId")
    v2 = r2.get("VersionId")
    assert v1 is not None, "VersionId not returned for first put"
    assert v2 is not None, "VersionId not returned for second put"
    assert v1 != v2, f"two puts returned same VersionId: {v1}"

    # Independent read at the destination: ListObjectVersions (not PutObject) must carry both
    # ids, and each id must resolve — via GetObject, a third operation — to the exact bytes that
    # put created it, ruling out a target that echoes a distinct string without storing anything.
    listed = s3.list_object_versions(Bucket=bucket, Prefix=key)["Versions"]
    listed_ids = {v["VersionId"] for v in listed}
    assert {v1, v2} <= listed_ids, f"expected versions {v1!r} and {v2!r} in ListObjectVersions, got {listed_ids}"
    latest = next(v for v in listed if v["VersionId"] == v2)
    assert latest["IsLatest"] is True, f"expected {v2!r} (the second put) marked IsLatest, got {latest}"

    body1 = s3.get_object(Bucket=bucket, Key=key, VersionId=v1)["Body"].read()
    body2 = s3.get_object(Bucket=bucket, Key=key, VersionId=v2)["Body"].read()
    assert body1 == b"version-1", f"GetObject(VersionId={v1!r}) returned {body1!r}, expected b'version-1'"
    assert body2 == b"version-2", f"GetObject(VersionId={v2!r}) returned {body2!r}, expected b'version-2'"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
