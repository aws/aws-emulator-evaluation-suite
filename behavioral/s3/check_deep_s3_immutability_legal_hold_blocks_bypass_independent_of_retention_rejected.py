"""deep-s3-immutability-legal-hold-blocks-bypass-independent-of-retention-rejected."""

from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-legal-hold-blocks-bypass-independent-of-retention-rejected"
GROUP = 'object-lock-rejection'
SERVICES = ['s3']

_HELD_BODY = b"retained-AND-held-bytes"
_CONTROL_BODY = b"retained-only-bytes"
_TEARDOWN_BUDGET_S = 240.0
_TEARDOWN_POLL_S = 10.0


def _delete_lock_bucket(client, bucket):
    """Empty an Object-Lock bucket (lifting legal holds, bypassing GOVERNANCE) and delete it.

    Polls within a bound for retention that has not yet lapsed rather than leaking the bucket."""
    deadline = time.monotonic() + _TEARDOWN_BUDGET_S
    while True:
        remaining = []
        try:
            for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
                for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                    if o not in page.get("DeleteMarkers", []):  # a delete marker holds no legal hold
                        try:
                            client.put_object_legal_hold(
                                Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"],
                                LegalHold={"Status": "OFF"},
                            )
                        except ClientError as exc:
                            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                                raise
                    try:
                        client.delete_object(
                            Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"],
                            BypassGovernanceRetention=True,
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "AccessDenied":  # retention not yet lapsed
                            raise
                        remaining.append((o["Key"], o["VersionId"]))
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
            break
        if not remaining or time.monotonic() >= deadline:
            break
        time.sleep(_TEARDOWN_POLL_S)
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_lock_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-imm-")
    params = {"Bucket": name, "ObjectLockEnabledForBucket": True}
    # us-east-1 is the one region that rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_lock_bucket(s3, name))
    return name


def _error(fn, what):
    """Call fn(); return the S3 (error code, error message) it raised. A SUCCESS is itself the
    failure."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"{what} unexpectedly SUCCEEDED (HTTP "
        f"{resp.get('ResponseMetadata', {}).get('HTTPStatusCode')!r}) where real AWS refuses it"
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Legal hold and retention are independent locks: a bypass delete that frees a retention-only
    version is refused on a held one, clearing retention leaves the hold in force, and only lifting
    the hold lets the version be deleted."""
    s3 = ctx.client("s3")
    bucket = _new_lock_bucket(ctx, s3)
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)

    held = s3.put_object(Bucket=bucket, Key="held.bin", Body=_HELD_BODY)["VersionId"]
    s3.put_object_retention(
        Bucket=bucket, Key="held.bin", VersionId=held,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": until},
    )
    s3.put_object_legal_hold(
        Bucket=bucket, Key="held.bin", VersionId=held, LegalHold={"Status": "ON"}
    )
    control = s3.put_object(Bucket=bucket, Key="control.bin", Body=_CONTROL_BODY)["VersionId"]
    s3.put_object_retention(
        Bucket=bucket, Key="control.bin", VersionId=control,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": until},
    )

    hold = s3.get_object_legal_hold(Bucket=bucket, Key="held.bin", VersionId=held)["LegalHold"]
    assert hold == {"Status": "ON"}, f"legal hold did not land: {hold!r}"

    # --- The bypass that lifts retention does NOT lift a legal hold.
    code = _error(
        lambda: s3.delete_object(
            Bucket=bucket, Key="held.bin", VersionId=held, BypassGovernanceRetention=True
        ),
        "a bypass DeleteObject of a GOVERNANCE-retained version that is also under legal hold",
    )
    assert code == ("AccessDenied", "Access Denied because object protected by object lock."), (
        f"expected AccessDenied for a bypass delete of a held version, got {code!r}"
    )
    body = s3.get_object(Bucket=bucket, Key="held.bin", VersionId=held)["Body"].read()
    assert body == _HELD_BODY, f"the refused delete altered the held version: {body!r}"

    # --- Positive control: the byte-identical bypass delete on the retention-only version works.
    ok = s3.delete_object(
        Bucket=bucket, Key="control.bin", VersionId=control, BypassGovernanceRetention=True
    )
    assert ok["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"the retention-only bypass delete returned {ok['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    gone = _error(
        lambda: s3.get_object(Bucket=bucket, Key="control.bin", VersionId=control),
        "reading the bypass-deleted control version",
    )
    assert gone == ("NoSuchVersion", "The specified version does not exist."), (
        f"expected the control version gone (NoSuchVersion), got {gone!r}"
    )

    # --- Remove the retention ENTIRELY: the hold alone still blocks deletion.
    s3.put_object_retention(
        Bucket=bucket, Key="held.bin", VersionId=held, BypassGovernanceRetention=True,
        Retention={},
    )
    no_ret = _error(
        lambda: s3.get_object_retention(Bucket=bucket, Key="held.bin", VersionId=held),
        "reading a retention that was just cleared",
    )
    assert no_ret == ("NoSuchObjectLockConfiguration", "The specified object does not have a ObjectLock configuration"), (
        f"expected NoSuchObjectLockConfiguration after clearing retention, got {no_ret!r}"
    )
    hold = s3.get_object_legal_hold(Bucket=bucket, Key="held.bin", VersionId=held)["LegalHold"]
    assert hold == {"Status": "ON"}, (
        f"clearing the retention changed the legal hold to {hold!r} — the two must be independent"
    )
    code = _error(
        lambda: s3.delete_object(Bucket=bucket, Key="held.bin", VersionId=held),
        "a DeleteObject of a version under legal hold with no retention at all",
    )
    assert code == ("AccessDenied", "Access Denied because object protected by object lock."), (
        f"expected AccessDenied deleting a held version with no retention, got {code!r}"
    )
    body = s3.get_object(Bucket=bucket, Key="held.bin", VersionId=held)["Body"].read()
    assert body == _HELD_BODY, f"the hold-only refusal altered the version: {body!r}"

    # --- Lift the hold: now, and only now, the plain delete frees the version.
    s3.put_object_legal_hold(
        Bucket=bucket, Key="held.bin", VersionId=held, LegalHold={"Status": "OFF"}
    )
    freed = s3.delete_object(Bucket=bucket, Key="held.bin", VersionId=held)
    assert freed.get("VersionId") == held, (
        f"the delete after lifting the hold reported VersionId {freed.get('VersionId')!r}, want {held!r}"
    )
    gone = _error(
        lambda: s3.get_object(Bucket=bucket, Key="held.bin", VersionId=held),
        "reading the version deleted after its hold was lifted",
    )
    assert gone == ("NoSuchVersion", "The specified version does not exist."), (
        f"expected NoSuchVersion after the freed delete, got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
