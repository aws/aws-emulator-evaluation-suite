"""bucket-acl-write-blocked-by-ownership-enforced."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-acl-write-blocked-by-ownership-enforced"
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


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketAcl on a BucketOwnerEnforced bucket fails with AccessControlListNotSupported and
    leaves grants unchanged; after switching to ObjectWriter the same call succeeds, so the
    rejection is attributable to ownership enforcement."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)  # default ownership: BucketOwnerEnforced
    # Block Public Access defaults to fully-blocking on a new bucket, which would itself reject
    # a public-read ACL with AccessDenied. Disable it so the rejection we observe is attributable
    # solely to BucketOwnerEnforced, not to the public-access-block feature.
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )

    before = s3.get_bucket_acl(Bucket=bucket)["Grants"]

    code, message = _client_error(lambda: s3.put_bucket_acl(Bucket=bucket, ACL="public-read"))
    assert code == "AccessControlListNotSupported", (
        f"expected the ACL mutation to be rejected with AccessControlListNotSupported on a "
        f"BucketOwnerEnforced bucket, got {code}"
    )
    assert message == "The bucket does not allow ACLs", f"unexpected message {message!r}"

    # the forbidden effect did not happen: grants are unchanged, still just owner FULL_CONTROL
    after = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    assert after == before, f"ACL grants changed despite the rejected mutation: {before} -> {after}"
    assert not any(g["Grantee"].get("Type") == "Group" for g in after), (
        f"a group grant leaked through despite the rejection: {after}"
    )

    # positive control: relaxing ownership on this same bucket to ObjectWriter re-enables ACLs,
    # and the identical PutBucketAcl call now succeeds
    s3.put_bucket_ownership_controls(
        Bucket=bucket,
        OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]},
    )
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
    grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    grantee_uris = {g["Grantee"].get("URI") for g in grants if g["Grantee"].get("Type") == "Group"}
    assert "http://acs.amazonaws.com/groups/global/AllUsers" in grantee_uris, (
        f"expected an AllUsers group grant once ownership was relaxed to ObjectWriter, got {grants}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
