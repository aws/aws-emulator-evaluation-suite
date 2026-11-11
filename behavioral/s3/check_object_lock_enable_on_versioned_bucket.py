"""object-lock-enable-on-versioned-bucket."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "object-lock-enable-on-versioned-bucket"
GROUP = 'object_lock'
SERVICES = ['s3']


def _delete_lock_bucket(client, bucket):
    """Empty an Object-Lock bucket (release legal holds + bypass GOVERNANCE) then delete it.

    COMPLIANCE-retained versions cannot be removed before their RetainUntilDate; this is
    best-effort and such a bucket may linger until the retention window elapses.
    """
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Object Lock CAN be enabled after bucket creation once versioning is Enabled; the
    default retention rule round-trips and new objects inherit it."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-lockbkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_lock_bucket(s3, name))

    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})

    s3.put_object_lock_configuration(
        Bucket=name,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
        },
    )

    cfg = s3.get_object_lock_configuration(Bucket=name)["ObjectLockConfiguration"]
    assert cfg["ObjectLockEnabled"] == "Enabled", f"lock not enabled: {cfg!r}"
    retention = cfg["Rule"]["DefaultRetention"]
    assert retention["Mode"] == "GOVERNANCE", f"default retention mode not preserved: {retention!r}"
    assert retention["Days"] == 1, f"default retention days not preserved: {retention!r}"

    # objects written afterwards inherit the bucket default retention
    before_put = datetime.now(timezone.utc)
    put = s3.put_object(Bucket=name, Key="auto-retained.txt", Body=b"x")
    got = s3.get_object_retention(
        Bucket=name, Key="auto-retained.txt", VersionId=put["VersionId"]
    )["Retention"]
    assert got["Mode"] == "GOVERNANCE", f"object did not inherit the default retention mode: {got!r}"
    retain_until = got.get("RetainUntilDate")
    assert retain_until is not None, f"inherited retention has no RetainUntilDate: {got!r}"
    # the bucket default is 1 day: the inherited window must land within that day of the write,
    # not merely be present, or a target that stamps an arbitrary far-future date would pass too.
    window_start = before_put + timedelta(hours=23)
    window_end = before_put + timedelta(hours=25)
    assert window_start <= retain_until <= window_end, (
        f"inherited RetainUntilDate {retain_until!r} is not ~1 day after the write at {before_put!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
