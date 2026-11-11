"""object-lock-ops-require-lock-enabled-bucket."""

from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "object-lock-ops-require-lock-enabled-bucket"
GROUP = 'object_lock'
SERVICES = ['s3']
NOT_LOCK_ENABLED_MESSAGE = 'Bucket is missing Object Lock Configuration'


def _delete_bucket(client, bucket, bypass_governance=False):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                kwargs = {"Bucket": bucket, "Key": o["Key"], "VersionId": o["VersionId"]}
                if bypass_governance:
                    kwargs["BypassGovernanceRetention"] = True
                client.delete_object(**kwargs)
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


def _new_bucket(ctx, s3, bypass_governance=False, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name, bypass_governance=bypass_governance))
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutObjectLegalHold and PutObjectRetention are rejected on a bucket created without Object
    Lock but succeed on a lock-enabled twin; reads on the unlocked bucket show nothing stored."""
    s3 = ctx.client("s3")
    key = "obj.txt"
    retain_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=6)

    locked = _new_bucket(ctx, s3, bypass_governance=True, ObjectLockEnabledForBucket=True)
    unlocked = _new_bucket(ctx, s3)  # no ObjectLockEnabledForBucket
    for name in (locked, unlocked):
        s3.put_object(Bucket=name, Key=key, Body=b"data")

    # positive control: the identical calls succeed on the lock-enabled twin
    s3.put_object_legal_hold(Bucket=locked, Key=key, LegalHold={"Status": "ON"})
    held = s3.get_object_legal_hold(Bucket=locked, Key=key)
    assert held["LegalHold"]["Status"] == "ON", held
    s3.put_object_legal_hold(Bucket=locked, Key=key, LegalHold={"Status": "OFF"})

    s3.put_object_retention(
        Bucket=locked, Key=key, Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until},
    )
    retention = s3.get_object_retention(Bucket=locked, Key=key)
    assert retention["Retention"]["Mode"] == "GOVERNANCE", retention

    # negative: both calls are rejected, with the specific error code, on the non-lock-enabled bucket
    code, message = _err(
        lambda: s3.put_object_legal_hold(Bucket=unlocked, Key=key, LegalHold={"Status": "ON"})
    )
    assert code == "InvalidRequest", f"expected InvalidRequest for PutObjectLegalHold, got {code!r}"
    assert message == NOT_LOCK_ENABLED_MESSAGE, f"unexpected PutObjectLegalHold message: {message!r}"

    code, message = _err(
        lambda: s3.put_object_retention(
            Bucket=unlocked, Key=key, Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until},
        )
    )
    assert code == "InvalidRequest", f"expected InvalidRequest for PutObjectRetention, got {code!r}"
    assert message == NOT_LOCK_ENABLED_MESSAGE, f"unexpected PutObjectRetention message: {message!r}"

    # effect absent: independent reads on the unlocked bucket confirm nothing stuck despite the rejected writes
    code, message = _err(lambda: s3.get_object_legal_hold(Bucket=unlocked, Key=key))
    assert code == "InvalidRequest", f"expected InvalidRequest reading legal hold, got {code!r}"
    assert message == NOT_LOCK_ENABLED_MESSAGE, f"unexpected GetObjectLegalHold message: {message!r}"

    code, message = _err(lambda: s3.get_object_retention(Bucket=unlocked, Key=key))
    assert code == "InvalidRequest", f"expected InvalidRequest reading retention, got {code!r}"
    assert message == NOT_LOCK_ENABLED_MESSAGE, f"unexpected GetObjectRetention message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
