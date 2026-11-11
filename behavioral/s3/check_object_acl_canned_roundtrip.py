"""object-acl-canned-roundtrip."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "object-acl-canned-roundtrip"
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
    """PutObjectAcl with a canned ACL replaces the grant list; GetObjectAcl reflects the new
    grants (owner FULL_CONTROL + public READ)."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    # Buckets created after Apr-2023 default to ObjectOwnership=BucketOwnerEnforced,
    # which DISABLES ACLs outright (PutObjectAcl -> AccessControlListNotSupported),
    # and to Block Public Access all-on. Both must be relaxed before a canned
    # public-read ACL is even expressible.
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]}
    )
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False, "IgnorePublicAcls": False,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
        },
    )
    key = "acl-object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"x")

    owner = s3.get_object_acl(Bucket=bucket, Key=key)["Owner"]

    # Grant something the canned ACL below does not mention, so the final read can tell
    # "replaces the grant list" (the contract) apart from "merges into it".
    s3.put_object_acl(
        Bucket=bucket, Key=key,
        AccessControlPolicy={
            "Owner": owner,
            "Grants": [
                {"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"},
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                    "Permission": "READ_ACP",
                },
            ],
        },
    )
    interim = s3.get_object_acl(Bucket=bucket, Key=key)
    assert any(g["Permission"] == "READ_ACP" for g in interim["Grants"]), (
        f"explicit LogDelivery READ_ACP grant must be visible before the canned ACL replaces it, "
        f"got grants={interim['Grants']}"
    )

    s3.put_object_acl(Bucket=bucket, Key=key, ACL="public-read")
    acl = s3.get_object_acl(Bucket=bucket, Key=key)
    assert acl["Owner"] == owner, "owner must not change when ACL is replaced"

    grantee_uris = {g["Grantee"].get("URI") for g in acl["Grants"] if g["Grantee"].get("Type") == "Group"}
    assert "http://acs.amazonaws.com/groups/global/AllUsers" in grantee_uris, (
        f"expected AllUsers group grant for public-read ACL, got grants={acl['Grants']}"
    )
    perms = {g["Permission"] for g in acl["Grants"]}
    assert "READ" in perms and "FULL_CONTROL" in perms, f"expected READ+FULL_CONTROL permissions, got {perms}"
    assert not any(g["Permission"] == "READ_ACP" for g in acl["Grants"]), (
        f"canned ACL must replace the prior grant list, but the LogDelivery READ_ACP grant "
        f"survived: {acl['Grants']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
