"""object-legal-hold-blocks-delete."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "object-legal-hold-blocks-delete"
GROUP = 'object_lock'
SERVICES = ['s3']
LOCKED_MESSAGE = 'Access Denied because object protected by object lock.'
NO_SUCH_VERSION_MESSAGE = 'The specified version does not exist.'


def _delete_lock_bucket(client, bucket):
    """Empty an Object-Lock bucket (release legal holds + bypass GOVERNANCE) then delete it."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                key, vid = v["Key"], v["VersionId"]
                if v not in page.get("DeleteMarkers", []):  # a delete marker holds no legal hold
                    try:
                        client.put_object_legal_hold(
                            Bucket=bucket, Key=key, VersionId=vid, LegalHold={"Status": "OFF"}
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                            raise
                try:
                    client.delete_object(
                        Bucket=bucket, Key=key, VersionId=vid, BypassGovernanceRetention=True
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_lock_bucket(ctx, s3):
    """Create a bucket with Object Lock enabled at creation (implies versioning); lock-aware teardown."""
    name = ctx.unique_name("sim2real-behav-lockbkt-")
    params = {"Bucket": name, "ObjectLockEnabledForBucket": True}
    # us-east-1 is S3's API-level default region and must NOT be passed as a
    # LocationConstraint (real S3 rejects that combination); every other region must be.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_lock_bucket(s3, name))
    return name


def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObject on a version under legal hold fails with AccessDenied and its exact message, even
    for the owner, and the version survives; after the hold is released the same delete succeeds and the
    version is NoSuchVersion."""
    s3 = ctx.client("s3")
    name = _new_lock_bucket(ctx, s3)
    key = "held.txt"
    put = s3.put_object(Bucket=name, Key=key, Body=b"held")
    version_id = put["VersionId"]

    s3.put_object_legal_hold(Bucket=name, Key=key, VersionId=version_id, LegalHold={"Status": "ON"})

    code, message = _err(lambda: s3.delete_object(Bucket=name, Key=key, VersionId=version_id))
    assert code == "AccessDenied", f"expected AccessDenied deleting a legal-hold version, got {code!r}"
    assert message == LOCKED_MESSAGE, f"unexpected AccessDenied message: {message!r}"

    # the forbidden effect did not happen: the version is still there, readable
    body = s3.get_object(Bucket=name, Key=key, VersionId=version_id)["Body"].read()
    assert body == b"held", f"expected version to survive the blocked delete, got body {body!r}"

    # release the hold, then the identical delete call succeeds, and an independent read
    # (a different operation than the one that mutated) proves the version is really gone
    s3.put_object_legal_hold(Bucket=name, Key=key, VersionId=version_id, LegalHold={"Status": "OFF"})
    s3.delete_object(Bucket=name, Key=key, VersionId=version_id)
    not_found, not_found_message = _err(lambda: s3.get_object(Bucket=name, Key=key, VersionId=version_id))
    assert not_found == "NoSuchVersion", f"expected NoSuchVersion after the real delete, got {not_found!r}"
    assert not_found_message == NO_SUCH_VERSION_MESSAGE, f"unexpected NoSuchVersion message: {not_found_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
