"""snapshot-copy-grant-lifecycle."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


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


def _message_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"].get("Message", "")
    return str(exc)


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


def _err(fn):
    """Call *fn*; return (AWS error code, message), or ("OK", "") if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc), _message_of(exc)
    return "OK", ""


def _probe_codes(cases):
    """{label: callable} -> {label: (error-code-or-"OK", message)}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}

CHECK = "snapshot-copy-grant-lifecycle"
GROUP = 'snapshot-copy'
SERVICES = ['redshift']


def _delete_unless_gone(delete, gone_code):
    """Teardown delete; an already-deleted resource answers ``gone_code`` (documented not-found)."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Snapshot copy grants: create binds a KMS key, describe finds it, delete removes it, an
    independent read then reports the grant gone, and a mutation on the dead id (a second delete)
    also fails not-found (delete is not idempotent)."""
    rs = ctx.client("redshift")
    grant_name = ctx.unique_name("sim2real-behav-rs-scg-")
    ctx.on_cleanup(lambda: _delete_unless_gone(
        lambda: rs.delete_snapshot_copy_grant(SnapshotCopyGrantName=grant_name),
        "SnapshotCopyGrantNotFoundFault"))
    created = rs.create_snapshot_copy_grant(
        SnapshotCopyGrantName=grant_name,
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )["SnapshotCopyGrant"]
    assert created["SnapshotCopyGrantName"] == grant_name, (
        f"expected {grant_name}, got {created['SnapshotCopyGrantName']}"
    )
    assert created["KmsKeyId"], "a grant must resolve to a KMS key (the account default when unspecified)"

    described = rs.describe_snapshot_copy_grants(
        SnapshotCopyGrantName=grant_name
    )["SnapshotCopyGrants"]
    assert len(described) == 1, described
    assert described[0]["KmsKeyId"] == created["KmsKeyId"], (
        f"expected {created['KmsKeyId']}, got {described[0]['KmsKeyId']}"
    )

    rs.delete_snapshot_copy_grant(SnapshotCopyGrantName=grant_name)

    gone_code, gone_message = _err(lambda: rs.describe_snapshot_copy_grants(SnapshotCopyGrantName=grant_name))
    assert gone_code == "SnapshotCopyGrantNotFoundFault", (
        f"expected an independent read to report the grant gone, got {gone_code}"
    )
    expected = f"Snapshot copy grant '{grant_name}' not found."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    code, message = _err(lambda: rs.delete_snapshot_copy_grant(SnapshotCopyGrantName=grant_name))
    assert code == "SnapshotCopyGrantNotFoundFault", f"expected SnapshotCopyGrantNotFoundFault, got {code}"
    expected = f"Snapshot copy grant not found: '{grant_name}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
