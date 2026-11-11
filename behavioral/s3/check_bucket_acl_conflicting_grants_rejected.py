"""bucket-acl-conflicting-grants-rejected."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-acl-conflicting-grants-rejected"
GROUP = 'acls_policies'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
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
    if ctx.region != "us-east-1":  # us-east-1 is the one region CreateBucket rejects a LocationConstraint for
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


_LOG_DELIVERY_URI = "http://acs.amazonaws.com/groups/s3/LogDelivery"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketAcl with both a canned ACL and an explicit grant header is rejected with InvalidRequest
    and its exact message and leaves the ACL unchanged; the positive control uses the non-public
    LogDelivery group so Block Public Access cannot mask it."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3, ObjectOwnership="BucketOwnerPreferred")

    # Positive control: a grant-header-only PutBucketAcl (no canned ACL) succeeds and is visible
    # on an independent read, proving the mutation path itself works on this bucket.
    s3.put_bucket_acl(Bucket=bucket, GrantWrite=f'uri="{_LOG_DELIVERY_URI}"')
    granted = s3.get_bucket_acl(Bucket=bucket)
    assert any(
        g["Grantee"].get("URI") == _LOG_DELIVERY_URI and g["Permission"] == "WRITE"
        for g in granted["Grants"]
    ), f"positive control failed: LogDelivery WRITE grant missing from {granted['Grants']}"

    # Reset to a known baseline (bare canned ACL, no grant header) before probing the conflict.
    s3.put_bucket_acl(Bucket=bucket, ACL="private")
    before = s3.get_bucket_acl(Bucket=bucket)["Grants"]

    code, message = _client_error(
        lambda: s3.put_bucket_acl(
            Bucket=bucket, ACL="private", GrantWrite=f'uri="{_LOG_DELIVERY_URI}"'
        )
    )
    assert code == "InvalidRequest", (
        f"expected InvalidRequest for a canned ACL combined with an explicit grant header, got {code}"
    )
    expected = "Specifying both Canned ACLs and Header Grants is not allowed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    assert after == before, (
        f"rejected PutBucketAcl must not change the bucket ACL: before={before} after={after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
