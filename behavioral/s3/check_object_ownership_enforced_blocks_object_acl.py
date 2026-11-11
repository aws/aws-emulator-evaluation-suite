"""object-ownership-enforced-blocks-object-acl."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "object-ownership-enforced-blocks-object-acl"
GROUP = "overly-permissive"
SERVICES = ["s3"]
ACLS_DISABLED_MESSAGE = 'The bucket does not allow ACLs'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Under BucketOwnerEnforced, PutObjectAcl is rejected with AccessControlListNotSupported and its
    exact message and GetObjectAcl still shows only the owner's FULL_CONTROL grant, while the same call
    on an ObjectWriter sibling bucket applies the AllUsers grant."""
    s3 = ctx.client("s3")

    enforced_bucket = ctx.unique_name("sim2real-ownenf-")
    _create_bucket(ctx, s3, enforced_bucket)
    # New buckets default to Block Public Access enabled, which would reject a
    # public-read ACL with AccessDenied regardless of ownership controls. Disable
    # it here so the PutObjectAcl failure we observe is attributable solely to
    # BucketOwnerEnforced (ACLs disabled), not to the public-access-block feature.
    s3.put_public_access_block(
        Bucket=enforced_bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_bucket_ownership_controls(
        Bucket=enforced_bucket,
        OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
    )
    key = "owned-object.txt"
    s3.put_object(Bucket=enforced_bucket, Key=key, Body=b"content")

    before_grants = s3.get_object_acl(Bucket=enforced_bucket, Key=key)["Grants"]

    err, message = _error(
        lambda: s3.put_object_acl(Bucket=enforced_bucket, Key=key, ACL="public-read")
    )
    assert err == "AccessControlListNotSupported", (
        f"expected AccessControlListNotSupported under BucketOwnerEnforced, got {err}"
    )
    assert message == ACLS_DISABLED_MESSAGE, f"unexpected AccessControlListNotSupported message: {message!r}"

    # the forbidden effect did not happen: ACL grants are unchanged, still just owner FULL_CONTROL
    after_grants = s3.get_object_acl(Bucket=enforced_bucket, Key=key)["Grants"]
    assert after_grants == before_grants, (
        f"expected grants unchanged by the rejected PutObjectAcl, before={before_grants!r} "
        f"after={after_grants!r}"
    )
    assert len(after_grants) == 1 and after_grants[0]["Permission"] == "FULL_CONTROL", (
        f"expected exactly one owner FULL_CONTROL grant, got {after_grants!r}"
    )
    assert not any(g["Grantee"].get("Type") == "Group" for g in after_grants), (
        f"expected no Group grantee (no public grant applied), got {after_grants!r}"
    )

    # positive control: an ObjectWriter-owned sibling bucket accepts the same PutObjectAcl call
    writer_bucket = ctx.unique_name("sim2real-ownwriter-")
    _create_bucket(ctx, s3, writer_bucket, ObjectOwnership="ObjectWriter")
    s3.put_public_access_block(
        Bucket=writer_bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_object(Bucket=writer_bucket, Key=key, Body=b"content")
    s3.put_object_acl(Bucket=writer_bucket, Key=key, ACL="public-read")
    grants = s3.get_object_acl(Bucket=writer_bucket, Key=key)["Grants"]
    grantee_uris = {g["Grantee"].get("URI") for g in grants if g["Grantee"].get("Type") == "Group"}
    assert "http://acs.amazonaws.com/groups/global/AllUsers" in grantee_uris, (
        f"expected the AllUsers group grant on the ObjectWriter sibling bucket, got {grants!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    # us-east-1 is CreateBucket's implicit default region; passing a LocationConstraint
    # for it is itself rejected, so it is the one region literal skipped here.
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
