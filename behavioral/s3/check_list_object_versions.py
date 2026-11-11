"""list-object-versions."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-object-versions"
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
    # us-east-1 is S3's original region: CreateBucket rejects an explicit LocationConstraint there.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectVersions returns all versions and delete markers, correctly identified and ordered."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    v1 = s3.put_object(Bucket=bucket, Key="lv-key", Body=b"v1").get("VersionId")
    v2 = s3.put_object(Bucket=bucket, Key="lv-key", Body=b"v2").get("VersionId")
    assert v1 and v2 and v1 != v2, f"expected two distinct version ids, got {v1!r} and {v2!r}"
    marker_id = s3.delete_object(Bucket=bucket, Key="lv-key").get("VersionId")
    assert marker_id and marker_id not in (v1, v2), (
        f"expected a delete-marker version id distinct from the data versions, got {marker_id!r} "
        f"against data versions {v1!r}, {v2!r}"
    )

    resp = s3.list_object_versions(Bucket=bucket, Prefix="lv-key")
    versions = resp.get("Versions", [])
    markers = resp.get("DeleteMarkers", [])
    assert len(versions) == 2, f"expected 2 versions, got {len(versions)}"
    assert len(markers) == 1, f"expected 1 delete marker, got {len(markers)}"

    by_version = {v["VersionId"]: v for v in versions}
    assert set(by_version) == {v1, v2}, (
        f"expected ListObjectVersions' Versions to be exactly {{{v1!r}, {v2!r}}}, got "
        f"{sorted(by_version)!r}"
    )
    assert markers[0]["VersionId"] == marker_id, (
        f"expected the listed delete marker's VersionId to be {marker_id!r}, got "
        f"{markers[0]['VersionId']!r}"
    )
    assert markers[0]["IsLatest"] is True, (
        f"the delete marker sits on top of the key and must be IsLatest, got "
        f"{markers[0]['IsLatest']!r}"
    )
    assert not any(v["IsLatest"] for v in versions), (
        f"no data version may be IsLatest once a delete marker is on top of the key: {versions!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
