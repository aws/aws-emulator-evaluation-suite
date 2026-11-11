"""acl-disabled-bucket-rejects-put-object-acl."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "acl-disabled-bucket-rejects-put-object-acl"
GROUP = 'acls_policies'
SERVICES = ['s3']

_ACL_NOT_SUPPORTED_MESSAGE = "The bucket does not allow ACLs"
_LOG_DELIVERY = "http://acs.amazonaws.com/groups/s3/LogDelivery"


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
    """On a BucketOwnerEnforced bucket PutObjectAcl is refused without effect: a private ACL with
    AccessControlListNotSupported, a public one with AccessDenied (Block Public Access applies
    first). The same call succeeds on an ObjectWriter sibling bucket, the positive control."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "acl-disabled.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"x")
    baseline_grants = s3.get_object_acl(Bucket=bucket, Key=key)["Grants"]

    # A *private* ACL is not a public grant, so Block Public Access cannot be what
    # rejects it; the only reason left is that ACLs are disabled on the bucket.
    code, message = _client_error(lambda: s3.put_object_acl(Bucket=bucket, Key=key, ACL="private"))
    assert code == "AccessControlListNotSupported", (
        f"expected AccessControlListNotSupported on a BucketOwnerEnforced bucket, got {code!r}"
    )
    assert message == _ACL_NOT_SUPPORTED_MESSAGE, f"unexpected message {message!r}"
    grants = s3.get_object_acl(Bucket=bucket, Key=key)["Grants"]
    assert grants == baseline_grants, (
        f"object ACL grants changed despite a rejected PutObjectAcl: {baseline_grants!r} -> {grants!r}"
    )

    # A *public* ACL trips Block Public Access first, which answers with a
    # different code -- the precedence between the two guards is itself behaviour.
    code, message = _client_error(lambda: s3.put_object_acl(Bucket=bucket, Key=key, ACL="public-read"))
    assert code == "AccessDenied", (
        f"expected AccessDenied (Block Public Access precedes the ACL-disabled check), got {code!r}"
    )
    # The message names the caller's own identity, read here rather than pinned.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        f'User: {caller_arn} is not authorized to perform: s3:PutObjectAcl on resource: '
        f'"arn:aws:s3:::{bucket}/{key}" because public ACLs are prevented by the BlockPublicAcls '
        f'setting in S3 Block Public Access.'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    grants = s3.get_object_acl(Bucket=bucket, Key=key)["Grants"]
    assert grants == baseline_grants, (
        f"object ACL grants changed despite a rejected PutObjectAcl: {baseline_grants!r} -> {grants!r}"
    )

    # By contrast, a canned ACL on PutObject that grants nothing beyond the bucket
    # owner is accepted as a no-op rather than refused...
    s3.put_object(Bucket=bucket, Key="acl2.txt", Body=b"x", ACL="private")

    # ...whereas PutBucketAcl, whose whole purpose is to set an ACL, is refused
    # even for the private canned ACL.
    baseline_bucket_grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    code, message = _client_error(lambda: s3.put_bucket_acl(Bucket=bucket, ACL="private"))
    assert code == "AccessControlListNotSupported", (
        f"expected PutBucketAcl to be refused with AccessControlListNotSupported, got {code!r}"
    )
    assert message == _ACL_NOT_SUPPORTED_MESSAGE, f"unexpected message {message!r}"
    bucket_grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    assert bucket_grants == baseline_bucket_grants, (
        f"bucket ACL grants changed despite a rejected PutBucketAcl: {baseline_bucket_grants!r} -> {bucket_grants!r}"
    )

    # Positive control: PutObjectAcl on a sibling bucket whose ownership control is ObjectWriter
    # (ACLs enabled) succeeds and has an observable effect -- ruling out an account-wide inability
    # to call PutObjectAcl at all, which would otherwise make every rejection above
    # indistinguishable from "PutObjectAcl never works here". The grant names the S3 log delivery
    # group, which is not public, so the sibling keeps Block Public Access on.
    writer_bucket = _new_bucket(ctx, s3, ObjectOwnership="ObjectWriter")
    s3.put_object(Bucket=writer_bucket, Key=key, Body=b"x")
    owner_id = s3.get_object_acl(Bucket=writer_bucket, Key=key)["Owner"]["ID"]
    s3.put_object_acl(
        Bucket=writer_bucket,
        Key=key,
        GrantFullControl=f"id={owner_id}",
        GrantRead=f"uri={_LOG_DELIVERY}",
    )
    writer_grants = s3.get_object_acl(Bucket=writer_bucket, Key=key)["Grants"]
    grantee_uris = {
        g["Grantee"].get("URI") for g in writer_grants if g["Grantee"].get("Type") == "Group"
    }
    assert grantee_uris == {_LOG_DELIVERY}, (
        f"expected the positive control's PutObjectAcl to apply exactly its log-delivery grant, "
        f"got {writer_grants!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
