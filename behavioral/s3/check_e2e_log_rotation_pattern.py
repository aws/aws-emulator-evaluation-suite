"""e2e-log-rotation-pattern."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "e2e-log-rotation-pattern"
GROUP = 'e2e_workflows'
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
        # us-east-1 is the CreateBucket default region; passing a LocationConstraint for it is rejected.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Log rotation with versioning: overwrite same key 3 times, verify all versions retrievable."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    key = "logs/app.log"
    contents = [b"log-entry-1: startup", b"log-entry-2: running", b"log-entry-3: shutdown"]
    version_ids = []

    # Write the same key 3 times (simulating log rotation with versioning)
    for content in contents:
        resp = s3.put_object(Bucket=bucket, Key=key, Body=content)
        vid = resp.get("VersionId")
        assert vid is not None, "VersionId not returned for versioned put"
        version_ids.append(vid)

    # ListObjectVersions: verify 3 versions exist for that key
    resp = s3.list_object_versions(Bucket=bucket, Prefix=key)
    versions = resp.get("Versions", [])
    assert len(versions) == 3, f"Expected 3 versions, got {len(versions)}"

    # Exactly one version is flagged latest, and it is the most recently written one.
    latest_flagged = [v for v in versions if v.get("IsLatest")]
    assert len(latest_flagged) == 1, (
        f"Expected exactly one IsLatest=True version, got {len(latest_flagged)}"
    )
    assert latest_flagged[0]["VersionId"] == version_ids[2], (
        f"Expected IsLatest version {version_ids[2]!r}, got {latest_flagged[0]['VersionId']!r}"
    )

    # Get the earliest version (first written) and verify it has the first content
    got_first = s3.get_object(Bucket=bucket, Key=key, VersionId=version_ids[0])["Body"].read()
    assert got_first == contents[0], (
        f"Expected first version content {contents[0]!r}, got {got_first!r}"
    )

    # Default GET returns the latest version
    got_latest = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got_latest == contents[2], f"Expected latest content {contents[2]!r}, got {got_latest!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
