"""bucket-acl-owner-full-control-default."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "bucket-acl-owner-full-control-default"
GROUP = 'acls_policies'
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
    """A default (BucketOwnerEnforced) bucket's ACL reports exactly one FULL_CONTROL grant to the owner."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    ownership = s3.get_bucket_ownership_controls(Bucket=bucket)
    rules = ownership["OwnershipControls"]["Rules"]
    assert rules and rules[0]["ObjectOwnership"] == "BucketOwnerEnforced", (
        f"expected the default ObjectOwnership to be BucketOwnerEnforced, got {rules!r}"
    )

    acl = s3.get_bucket_acl(Bucket=bucket)
    owner_id = acl["Owner"]["ID"]
    assert owner_id, f"expected a non-empty owner canonical id, got {acl['Owner']!r}"

    grants = acl["Grants"]
    assert len(grants) == 1, f"expected exactly 1 grant on a fresh bucket, got {grants}"
    assert grants[0]["Permission"] == "FULL_CONTROL", f"expected FULL_CONTROL, got {grants[0]!r}"
    assert grants[0]["Grantee"].get("ID") == owner_id, "the sole grant must be to the bucket owner"
    assert grants[0]["Grantee"].get("Type") == "CanonicalUser", (
        f"expected the sole grant's Grantee.Type to be CanonicalUser, got {grants[0]['Grantee']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
