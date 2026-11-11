"""deep-s3-immutability-compliance-lock-extends-and-overwrites-but-weakening-rejected."""

from __future__ import annotations

import datetime
import email.utils
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-compliance-lock-extends-and-overwrites-but-weakening-rejected"
GROUP = 'object-lock-rejection'
SERVICES = ['s3']

_V1 = b"compliance-locked-original"
_V2 = b"overwrite-as-a-new-version"

#: COMPLIANCE retention cannot be undone by any principal until it lapses, so it is kept short
#: and the check body waits the lapse out itself, keeping teardown within its bounded budget.
_RETAIN_S = 12
_EXTEND_S = 8
_LAPSE_BUDGET_S = 150.0
_LAPSE_POLL_S = 1.0
_TEARDOWN_BUDGET_S = 50.0
_TEARDOWN_POLL_S = 2.0


def _delete_lock_bucket(client, bucket):
    """Empty an Object-Lock bucket (lifting legal holds, bypassing GOVERNANCE) and delete it,
    bounded-polling out any retention that has not yet lapsed rather than leaking the bucket."""
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A COMPLIANCE lock is per-version and ratchet-only: it can be extended and the key overwritten
    or delete-marked, but downgrade and clear are AccessDenied even with bypass, and the version
    stays undeletable until the extended date by the server's clock.
    """
    s3 = ctx.client("s3")
    bucket = _new_lock_bucket(ctx, s3)
    key = "ledger.bin"

    v1 = s3.put_object(Bucket=bucket, Key=key, Body=_V1)["VersionId"]
    until = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=_RETAIN_S)
    ).replace(microsecond=0)
    s3.put_object_retention(
        Bucket=bucket, Key=key, VersionId=v1,
        Retention={"Mode": "COMPLIANCE", "RetainUntilDate": until},
    )

    # --- Positive: an extension of a COMPLIANCE date is permitted and reads back.
    extended = until + datetime.timedelta(seconds=_EXTEND_S)
    s3.put_object_retention(
        Bucket=bucket, Key=key, VersionId=v1,
        Retention={"Mode": "COMPLIANCE", "RetainUntilDate": extended},
    )
    ret = s3.get_object_retention(Bucket=bucket, Key=key, VersionId=v1)["Retention"]
    assert ret["Mode"] == "COMPLIANCE", f"the extension changed the mode: {ret!r}"
    assert abs((ret["RetainUntilDate"] - extended).total_seconds()) < 1.0, (
        f"the extension read back RetainUntilDate {ret['RetainUntilDate']!r}; want {extended!r}"
    )

    # --- Negative 1: downgrading COMPLIANCE to GOVERNANCE, even with the bypass header.
    code = _error(
        lambda: s3.put_object_retention(
            Bucket=bucket, Key=key, VersionId=v1, BypassGovernanceRetention=True,
            Retention={"Mode": "GOVERNANCE", "RetainUntilDate": extended},
        ),
        "downgrading a COMPLIANCE retention to GOVERNANCE",
    )
    assert code == ("AccessDenied", "Access Denied because object protected by object lock."), (
        f"expected AccessDenied downgrading COMPLIANCE, got {code!r}"
    )

    # --- Negative 2: clearing the COMPLIANCE retention, even with the bypass header.
    code = _error(
        lambda: s3.put_object_retention(
            Bucket=bucket, Key=key, VersionId=v1, BypassGovernanceRetention=True, Retention={},
        ),
        "clearing a COMPLIANCE retention",
    )
    assert code == ("AccessDenied", "Access Denied because object protected by object lock."), (
        f"expected AccessDenied clearing COMPLIANCE, got {code!r}"
    )

    # Effect absent: neither refusal weakened the lock.
    ret = s3.get_object_retention(Bucket=bucket, Key=key, VersionId=v1)["Retention"]
    assert ret["Mode"] == "COMPLIANCE" and abs(
        (ret["RetainUntilDate"] - extended).total_seconds()
    ) < 1.0, f"a refused weakening changed the retention to {ret!r}"

    # --- Positive: the KEY is still writable — the PUT lands as a NEW, unlocked version.
    put2 = s3.put_object(Bucket=bucket, Key=key, Body=_V2)
    v2 = put2["VersionId"]
    assert v2 != v1, f"the overwrite reused the locked VersionId {v1!r}"
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["VersionId"] == v2, (
        f"the current version is {head['VersionId']!r}; the overwrite {v2!r} should be current"
    )
    assert "ObjectLockMode" not in head, (
        f"the new version inherited ObjectLockMode {head.get('ObjectLockMode')!r}; locks are "
        "per-version and this bucket has no default retention"
    )
    current = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert current == _V2, f"a versionless GET returned {current!r}, want the overwrite {_V2!r}"

    # --- Positive: a simple DELETE of the key is allowed — it writes a delete marker.
    marker = s3.delete_object(Bucket=bucket, Key=key)
    assert marker.get("DeleteMarker") is True, (
        f"a versionless DELETE on a key with a locked version returned {marker!r}; "
        "want a delete marker"
    )
    hidden = _error(
        lambda: s3.get_object(Bucket=bucket, Key=key),
        "a versionless GET behind a delete marker",
    )
    assert hidden == ("NoSuchKey", "The specified key does not exist."), (
        f"expected NoSuchKey behind the delete marker, got {hidden!r}"
    )

    # --- The locked version is untouched by all of it, and still refuses a version delete.
    locked = s3.get_object(Bucket=bucket, Key=key, VersionId=v1)
    assert locked["Body"].read() == _V1, "the locked version's bytes changed"
    assert locked.get("ObjectLockMode") == "COMPLIANCE", (
        f"GetObject on the locked version reported ObjectLockMode {locked.get('ObjectLockMode')!r}"
    )
    code = _error(
        lambda: s3.delete_object(
            Bucket=bucket, Key=key, VersionId=v1, BypassGovernanceRetention=True
        ),
        "a bypass version-delete of a COMPLIANCE version",
    )
    assert code == ("AccessDenied", "Access Denied because object protected by object lock."), (
        f"expected AccessDenied deleting the COMPLIANCE version, got {code!r}"
    )

    versions = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key):
        versions += [v["VersionId"] for v in page.get("Versions", []) if v["Key"] == key]
    assert sorted(versions) == sorted([v1, v2]), (
        f"the key's versions are {versions!r}; want exactly the locked {v1!r} and the overwrite {v2!r}"
    )

    # Poll until the lock lapses; checked against the server Date so an emulator enforcing the
    # original date fails. The bound asserts that the lapse arrives, not how fast.
    lapse_budget_s = _budget_s(ctx, _LAPSE_BUDGET_S)
    deadline = time.monotonic() + lapse_budget_s
    freed = None
    while freed is None:
        try:
            freed = s3.delete_object(Bucket=bucket, Key=key, VersionId=v1)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = (err.get("Code"), err.get("Message"))
            assert code == ("AccessDenied", "Access Denied because object protected by object lock."), (
                f"unexpected error while the lock was live: {code!r}"
            )
            if time.monotonic() >= deadline and _budget_spent(ctx):
                raise TimeoutError("the COMPLIANCE lock to lapse: the run budget ended first; not graded")
            assert time.monotonic() < deadline, (
                f"the COMPLIANCE version was still undeletable {lapse_budget_s:.0f}s after the run "
                f"began waiting; its RetainUntilDate was {extended!r}"
            )
            time.sleep(_LAPSE_POLL_S)
    server_now = email.utils.parsedate_to_datetime(freed["ResponseMetadata"]["HTTPHeaders"]["date"])
    assert server_now >= extended - datetime.timedelta(seconds=1), (
        f"the COMPLIANCE version was deleted at server time {server_now!r}, BEFORE its extended "
        f"RetainUntilDate {extended!r} — the extension was accepted but not enforced"
    )
    gone = _error(
        lambda: s3.get_object(Bucket=bucket, Key=key, VersionId=v1),
        "reading the COMPLIANCE version after its lapse-delete",
    )
    assert gone == ("NoSuchVersion", "The specified version does not exist."), (
        f"expected NoSuchVersion after the lapse-delete, got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
