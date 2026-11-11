"""op-schedule-deletion-window-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-schedule-deletion-window-out-of-range-rejected"
GROUP = 'key_lifecycle'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _schedule_deletion_if_needed(kms, key_id):
    """Teardown: the positive control schedules the deletion itself, so a key already
    PendingDeletion is fine."""
    if kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] != "PendingDeletion":
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PendingWindowInDays outside 7..30 must be rejected without mutating key state; the
    identical call with an in-range window must then succeed on the same key, so "rejects 6 and
    31" cannot be confused with "rejects every ScheduleKeyDeletion call"."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("kms-op-window-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: _schedule_deletion_if_needed(kms, _k))

    out_of_range = "PendingWindowInDays must be between 7 and 30"
    low, low_msg = _error(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=6))
    assert low == "ValidationException", f"expected ValidationException for 6 days, got {low}"
    assert low_msg == out_of_range, f"6 days -> unexpected message {low_msg!r}"

    high, high_msg = _error(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=31))
    assert high == "ValidationException", f"expected ValidationException for 31 days, got {high}"
    assert high_msg == out_of_range, f"31 days -> unexpected message {high_msg!r}"

    # rejected requests must not have partially applied
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"key must remain Enabled after rejected deletions, got {state}"

    # positive control: the identical operation with an in-range window on the identical key
    # must succeed -- proves the rejections above are a range check, not a wholesale failure
    resp = kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    assert "DeletionDate" in resp, f"expected DeletionDate in response, got {resp}"
    final_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert final_state == "PendingDeletion", (
        f"key must transition to PendingDeletion after an in-range deletion, got {final_state}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
