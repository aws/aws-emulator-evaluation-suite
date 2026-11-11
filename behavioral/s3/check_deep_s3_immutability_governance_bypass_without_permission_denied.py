"""deep-s3-immutability-governance-bypass-without-permission-denied."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-immutability-governance-bypass-without-permission-denied"
GROUP = 'object-lock-rejection'
SERVICES = ['s3']

_BODY = b"governance-retained-bytes-only-a-permitted-bypass-may-remove"
_KEY = "governed.bin"
_TEARDOWN_BUDGET_S = 240.0
_TEARDOWN_POLL_S = 10.0
_CONVERGE_S = 60.0


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


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """Under a Deny of s3:BypassGovernanceRetention, bypass delete and shorten are refused and
    change nothing while an extension succeeds; once the policy is removed the identical bypass
    delete succeeds, because the bypass header alone does not authorize lifting GOVERNANCE."""
    s3 = ctx.client("s3")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    bucket = _new_lock_bucket(ctx, s3)

    version = s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY)["VersionId"]
    until = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).replace(
        microsecond=0
    )
    s3.put_object_retention(
        Bucket=bucket, Key=_KEY, VersionId=version,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": until},
    )
    ret = s3.get_object_retention(Bucket=bucket, Key=_KEY, VersionId=version)["Retention"]
    assert ret["Mode"] == "GOVERNANCE", f"retention did not land as GOVERNANCE: {ret!r}"

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyGovernanceBypass",
            "Effect": "Deny",
            "Principal": {"AWS": caller_arn},
            "Action": "s3:BypassGovernanceRetention",
            "Resource": f"arn:aws:s3:::{bucket}/*",
        }],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    bypass_denied = (
        f"User: {caller_arn} is not authorized to perform: s3:BypassGovernanceRetention on "
        f"resource: \"arn:aws:s3:::{bucket}/{_KEY}\" with an explicit deny in a resource-based "
        f"policy"
    )
    # LIFO: this runs BEFORE the bucket teardown registered above, whose bypass deletes need it gone.
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=bucket))

    # --- The header without the permission: the delete is refused.
    code = _error(
        lambda: s3.delete_object(
            Bucket=bucket, Key=_KEY, VersionId=version, BypassGovernanceRetention=True
        ),
        "a bypass DeleteObject by a caller explicitly denied s3:BypassGovernanceRetention",
    )
    assert code == ("AccessDenied", bypass_denied), (
        f"expected AccessDenied for a bypass delete without the bypass permission, got {code!r}"
    )
    body = s3.get_object(Bucket=bucket, Key=_KEY, VersionId=version)["Body"].read()
    assert body == _BODY, f"the refused bypass delete altered the version: it holds {body!r}"

    # --- Shortening a GOVERNANCE date is the other bypass-gated act, and is refused the same way.
    shorter = until - datetime.timedelta(minutes=30)
    code = _error(
        lambda: s3.put_object_retention(
            Bucket=bucket, Key=_KEY, VersionId=version, BypassGovernanceRetention=True,
            Retention={"Mode": "GOVERNANCE", "RetainUntilDate": shorter},
        ),
        "a bypass shortening of GOVERNANCE retention without the bypass permission",
    )
    assert code == ("AccessDenied", bypass_denied), (
        f"expected AccessDenied shortening GOVERNANCE retention without the permission, got {code!r}"
    )
    after = s3.get_object_retention(Bucket=bucket, Key=_KEY, VersionId=version)["Retention"]
    assert abs((after["RetainUntilDate"] - until).total_seconds()) < 1.0, (
        f"the refused shorten moved RetainUntilDate to {after['RetainUntilDate']!r}; want {until!r}"
    )

    # --- Positive control under the SAME policy: extending needs no bypass, so it succeeds.
    extended = until + datetime.timedelta(minutes=30)
    s3.put_object_retention(
        Bucket=bucket, Key=_KEY, VersionId=version,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": extended},
    )
    after = s3.get_object_retention(Bucket=bucket, Key=_KEY, VersionId=version)["Retention"]
    assert after["Mode"] == "GOVERNANCE" and abs(
        (after["RetainUntilDate"] - extended).total_seconds()
    ) < 1.0, (
        f"an extension under the bypass-deny policy read back as {after!r}; want GOVERNANCE until "
        f"{extended!r} — the Deny must gate the bypass, not every retention write"
    )

    # --- Restore the permission. Policy removal propagates eventually, so poll for acceptance.
    s3.delete_bucket_policy(Bucket=bucket)
    deadline = time.monotonic() + _CONVERGE_S
    deleted = None
    last = None
    while deleted is None:
        try:
            deleted = s3.delete_object(
                Bucket=bucket, Key=_KEY, VersionId=version, BypassGovernanceRetention=True
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last = (err.get("Code"), err.get("Message"))
            assert last == ("AccessDenied", bypass_denied), (
                f"unexpected error during the permitted bypass: {last!r}"
            )
            assert time.monotonic() < deadline, (
                f"a bypass delete was still refused {_CONVERGE_S}s after the Deny policy was removed"
            )
            time.sleep(2.0)
    assert deleted["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"the permitted bypass delete returned {deleted['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    assert deleted.get("VersionId") == version, (
        f"the permitted bypass delete reported VersionId {deleted.get('VersionId')!r}, want {version!r}"
    )
    gone = _error(
        lambda: s3.get_object(Bucket=bucket, Key=_KEY, VersionId=version),
        "reading a version the permitted bypass just deleted",
    )
    assert gone == ("NoSuchVersion", "The specified version does not exist."), (
        f"expected NoSuchVersion after the bypass delete, got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
