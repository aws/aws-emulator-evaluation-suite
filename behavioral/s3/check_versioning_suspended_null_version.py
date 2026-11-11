"""versioning-suspended-null-version."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "versioning-suspended-null-version"
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
    """While versioning is Suspended, PutObject writes/overwrites the single version-id 'null' object
    in place, and the numbered version created while versioning was Enabled survives untouched."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    r1 = s3.put_object(Bucket=bucket, Key="k", Body=b"enabled-version")
    v1 = r1.get("VersionId")
    assert v1 not in (None, "null"), f"expected a real version id for the Enabled-state write, got {v1!r}"

    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Suspended"})
    status = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    assert status == "Suspended", f"expected Suspended, got {status!r}"

    resp = s3.put_object(Bucket=bucket, Key="k", Body=b"suspended-write-1")
    assert resp.get("VersionId") is None, f"PutObject must omit VersionId for a Suspended-state write, got {resp.get('VersionId')!r}"

    versions = s3.list_object_versions(Bucket=bucket, Prefix="k").get("Versions", [])
    ids = {v["VersionId"] for v in versions}
    assert v1 in ids, f"the numbered Enabled-state version must survive a Suspended overwrite, got {sorted(ids)}"
    null_versions = [v for v in versions if v["VersionId"] == "null"]
    assert len(null_versions) == 1, f"expected exactly one null version after the first Suspended write, got {len(null_versions)}"

    s3.put_object(Bucket=bucket, Key="k", Body=b"suspended-write-2")
    versions2 = s3.list_object_versions(Bucket=bucket, Prefix="k").get("Versions", [])
    null_versions2 = [v for v in versions2 if v["VersionId"] == "null"]
    assert len(null_versions2) == 1, f"a second Suspended write must overwrite the null version in place, not append, got {len(null_versions2)}"
    ids2 = {v["VersionId"] for v in versions2}
    assert v1 in ids2, f"the numbered Enabled-state version must still survive after the second Suspended write, got {sorted(ids2)}"

    current = s3.get_object(Bucket=bucket, Key="k")
    assert current["Body"].read() == b"suspended-write-2", "GetObject must return the latest Suspended-state write"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
