"""create-snapshot-copy-grant-invalid-kms-key-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-snapshot-copy-grant-invalid-kms-key-rejected"
GROUP = "snapshot-copy"
SERVICES = ["redshift"]

_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _error(fn):
    """(code, message) fn() raises; an unexpected success raises instead of returning a sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSnapshotCopyGrant with a nonexistent KmsKeyId fails with InvalidParameterValue and leaves no
    grant behind; a grant naming a real customer managed key is accepted and echoes the key back.
    """
    rs = ctx.client("redshift")
    kms = ctx.client("kms")

    bad_name = ctx.unique_name("sim2real-behav-rs-scg-badkey-")
    bogus_key_arn = (
        f"arn:aws:kms:{ctx.region}:{ctx.account}:key/00000000-0000-0000-0000-000000000000"
    )
    code, bad_message = _error(lambda: rs.create_snapshot_copy_grant(
        SnapshotCopyGrantName=bad_name, KmsKeyId=bogus_key_arn
    ))
    # Effect absent: the rejected create must not have left a grant behind under this name.
    gone_code, gone_message = _error(
        lambda: rs.describe_snapshot_copy_grants(SnapshotCopyGrantName=bad_name))
    assert (code, gone_code) == ("InvalidParameterValue", "SnapshotCopyGrantNotFoundFault"), (
        f"expected InvalidParameterValue for a KmsKeyId naming no real key and then "
        f"SnapshotCopyGrantNotFoundFault for the name it was refused under, got {(code, gone_code)!r}"
    )
    want = (f"Unable to create snapshot copy grant. The KMS key '{bogus_key_arn}' does not exist "
            f"or is inaccessible.",
            f"Snapshot copy grant '{bad_name}' not found.")
    assert (bad_message, gone_message) == want, (
        f"expected messages {want!r}, got {(bad_message, gone_message)!r}"
    )

    # Positive control: a customer managed key this check creates is a real KmsKeyId, and an
    # explicit (valid) KmsKeyId is accepted and echoed back exactly, proving the parameter itself
    # works -- the rejection above is about the key's reality, not the parameter's shape.
    key = _retrying(lambda: kms.create_key(
        Description=ctx.unique_name("sim2real-behav-rs-scg-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    ))["KeyMetadata"]
    real_key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=real_key_arn, PendingWindowInDays=7))
    good_name = ctx.unique_name("sim2real-behav-rs-scg-goodkey-")
    ctx.on_cleanup(lambda: rs.delete_snapshot_copy_grant(SnapshotCopyGrantName=good_name))
    created = _retrying(lambda: rs.create_snapshot_copy_grant(
        SnapshotCopyGrantName=good_name, KmsKeyId=real_key_arn
    ))["SnapshotCopyGrant"]
    assert created["KmsKeyId"] == real_key_arn, (
        f"expected the explicit KmsKeyId {real_key_arn!r} to be used verbatim (as the full ARN), "
        f"got {created['KmsKeyId']!r}"
    )
    listed = rs.describe_snapshot_copy_grants(SnapshotCopyGrantName=good_name)["SnapshotCopyGrants"]
    assert [(g["SnapshotCopyGrantName"], g["KmsKeyId"]) for g in listed] == [
        (good_name, real_key_arn)], f"DescribeSnapshotCopyGrants serves {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
