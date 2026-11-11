"""object-retention-roundtrip."""

from __future__ import annotations
import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "object-retention-roundtrip"
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
    # us-east-1 is CreateBucket's implicit default region; passing an explicit
    # LocationConstraint of "us-east-1" is itself rejected, so it must be omitted.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_lock_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectRetention settings are reflected by GetObjectRetention, and an
    extension of RetainUntilDate (allowed under GOVERNANCE with bypass) is also
    reflected."""
    s3 = ctx.client("s3")
    name = _new_lock_bucket(ctx, s3)
    key = "retained.txt"
    s3.put_object(Bucket=name, Key=key, Body=b"data")

    retain_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=20)
    s3.put_object_retention(
        Bucket=name, Key=key, Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until}
    )
    fetched = s3.get_object_retention(Bucket=name, Key=key)["Retention"]
    assert fetched["Mode"] == "GOVERNANCE", f"expected Mode GOVERNANCE, got {fetched['Mode']}"
    assert abs((fetched["RetainUntilDate"] - retain_until).total_seconds()) < 5, (
        f"expected RetainUntilDate ~= {retain_until}, got {fetched['RetainUntilDate']}"
    )

    extended = retain_until + datetime.timedelta(minutes=20)
    s3.put_object_retention(
        Bucket=name,
        Key=key,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": extended},
        BypassGovernanceRetention=True,
    )
    fetched2 = s3.get_object_retention(Bucket=name, Key=key)["Retention"]
    assert abs((fetched2["RetainUntilDate"] - extended).total_seconds()) < 5, (
        f"expected extended RetainUntilDate ~= {extended}, got {fetched2['RetainUntilDate']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
