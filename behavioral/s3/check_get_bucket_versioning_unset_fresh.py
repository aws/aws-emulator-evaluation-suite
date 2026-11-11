"""get-bucket-versioning-unset-fresh."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "get-bucket-versioning-unset-fresh"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh bucket has NO versioning status at all -- 'unset' is a third state distinct from Enabled/Suspended."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    resp = s3.get_bucket_versioning(Bucket=bucket)
    assert "Status" not in resp, f"fresh bucket must report no versioning Status, got {resp.get('Status')!r}"
    assert "MFADelete" not in resp, f"fresh bucket must report no MFADelete, got {resp.get('MFADelete')!r}"

    # ... and it becomes observable only after an explicit transition
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    after = s3.get_bucket_versioning(Bucket=bucket)
    assert after.get("Status") == "Enabled", f"expected Status='Enabled' after PutBucketVersioning, got {after.get('Status')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
