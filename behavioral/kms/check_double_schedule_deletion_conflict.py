"""double-schedule-deletion-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "double-schedule-deletion-conflict"
GROUP = 'key_lifecycle'
SERVICES = ['kms']


def _error(fn):
    """Return the botocore Error dict fn() raises. An unexpected success raises, so a target
    that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _schedule_deletion_tolerant(kms, key_id):
    """Teardown: schedule deletion unless the key is already pending deletion."""
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "KMSInvalidStateException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Scheduling deletion on a key already pending deletion must raise KMSInvalidStateException,
    the rejected calls must not budge the key out of PendingDeletion, and cancelling deletion must
    restore the key to where the identical call succeeds."""
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("kms-doublesched-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    pending_message = f"{key['Arn']} is pending deletion."
    ctx.on_cleanup(lambda: _schedule_deletion_tolerant(kms, key_id))

    kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyState"] == "PendingDeletion", described["KeyState"]

    err = _error(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    assert err.get("Code") == "KMSInvalidStateException", f"expected KMSInvalidStateException, got {err}"
    assert err.get("Message") == pending_message, f"expected {pending_message!r}, got {err}"

    # also confirm disabling a pending-deletion key is rejected (state guard applies broadly)
    err2 = _error(lambda: kms.disable_key(KeyId=key_id))
    assert err2.get("Code") == "KMSInvalidStateException", f"expected KMSInvalidStateException, got {err2}"
    assert err2.get("Message") == pending_message, f"expected {pending_message!r}, got {err2}"

    # neither rejected call may have budged the key out of PendingDeletion
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyState"] == "PendingDeletion", (
        f"a rejected ScheduleKeyDeletion/DisableKey must not change key state, got {described['KeyState']}"
    )

    kms.cancel_key_deletion(KeyId=key_id)

    # CancelKeyDeletion restores to Disabled, not Enabled -- independent read at the destination
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyState"] == "Disabled", described["KeyState"]

    # the identical call rejected above now succeeds against the restored key
    kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyState"] == "PendingDeletion", described["KeyState"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
