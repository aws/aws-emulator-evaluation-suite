"""object-legal-hold-roundtrip."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "object-legal-hold-roundtrip"
GROUP = 'object_lock'
SERVICES = ['s3']


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
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_lock_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectLegalHold status transitions (ON -> OFF -> ON) are reflected by
    GetObjectLegalHold."""
    s3 = ctx.client("s3")
    name = _new_lock_bucket(ctx, s3)
    key = "legalhold.txt"
    s3.put_object(Bucket=name, Key=key, Body=b"data")

    s3.put_object_legal_hold(Bucket=name, Key=key, LegalHold={"Status": "ON"})
    status1 = s3.get_object_legal_hold(Bucket=name, Key=key)["LegalHold"]["Status"]
    assert status1 == "ON", f"expected legal hold ON after put, got {status1!r}"

    s3.put_object_legal_hold(Bucket=name, Key=key, LegalHold={"Status": "OFF"})
    status2 = s3.get_object_legal_hold(Bucket=name, Key=key)["LegalHold"]["Status"]
    assert status2 == "OFF", f"expected legal hold OFF after put, got {status2!r}"

    s3.put_object_legal_hold(Bucket=name, Key=key, LegalHold={"Status": "ON"})
    status3 = s3.get_object_legal_hold(Bucket=name, Key=key)["LegalHold"]["Status"]
    assert status3 == "ON", f"expected legal hold ON after second put, got {status3!r}"

    # Release before teardown so cleanup's own force-delete doesn't have to.
    s3.put_object_legal_hold(Bucket=name, Key=key, LegalHold={"Status": "OFF"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
