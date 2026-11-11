"""cancel-key-deletion."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cancel-key-deletion"
GROUP = 'key_lifecycle'
SERVICES = ['kms']


def _wait_for_state(describe, state: str, *, timeout_s: float = 30, interval_s: float = 2) -> dict:
    """Poll DescribeKey until KeyState reaches `state`, or raise.

    KMS's metadata plane is eventually consistent: DescribeKey can still echo the
    pre-mutation KeyState for a short window after ScheduleKeyDeletion/CancelKeyDeletion
    return, so the read is polled.
    """
    deadline = time.monotonic() + timeout_s
    last = describe()
    while last["KeyState"] != state:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"KeyState did not reach {state!r} within {timeout_s}s; last observed {last!r}"
            )
        time.sleep(interval_s)
        last = describe()
    return last


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelKeyDeletion restores a PendingDeletion key to Disabled state."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    schedule_resp = kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    assert "DeletionDate" in schedule_resp, f"ScheduleKeyDeletion must return a DeletionDate: {schedule_resp}"
    # Positive control: prove the key actually reached PendingDeletion before cancelling it,
    # via an independent read — otherwise a target that never implements scheduling still
    # passes as long as it reports "Disabled" after CancelKeyDeletion. (DescribeKey's own
    # DeletionDate can lag KeyState, so only KeyState is
    # re-asserted here; DeletionDate is checked above on the mutating call's own response.)
    pending = _wait_for_state(lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"], "PendingDeletion")
    assert pending["KeyState"] == "PendingDeletion", pending["KeyState"]

    kms.cancel_key_deletion(KeyId=key_id)

    # After cancellation, key is Disabled (not automatically re-enabled).
    meta = _wait_for_state(lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"], "Disabled")
    assert meta["KeyState"] == "Disabled", f"expected Disabled after CancelKeyDeletion, got {meta['KeyState']}"
    assert "DeletionDate" not in meta, f"DeletionDate must be cleared after cancellation, got {meta.get('DeletionDate')}"
    # Re-enable for cleanup
    kms.enable_key(KeyId=key_id)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
