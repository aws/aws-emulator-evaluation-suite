"""schedule-cancel-key-deletion."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "schedule-cancel-key-deletion"
GROUP = 'key-lifecycle'
SERVICES = ['kms']


def _wait_until(fn, predicate, timeout_s: float = 90, interval_s: float = 3):
    """Bounded poll: return the first value of fn() satisfying predicate.

    KMS's metadata plane is explicitly eventually consistent, so reads that follow a
    mutation must be retried rather than asserted once. Raises AssertionError with the
    last observed value on timeout, which keeps the failure mode distinct from a genuine
    behavioural mismatch.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = fn()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not reached within {timeout_s}s; last observed value: {last!r}"
            )
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ScheduleKeyDeletion moves key to PendingDeletion; CancelKeyDeletion returns it to Disabled."""
    kms = ctx.client("kms")
    meta = kms.create_key(Description=ctx.unique_name("sim2real-behav-kms-sched-"))["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    resp = kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    assert resp["KeyState"] == "PendingDeletion", resp["KeyState"]
    assert "DeletionDate" in resp, f"ScheduleKeyDeletion response missing DeletionDate: {resp!r}"

    # DescribeKey's metadata plane is eventually consistent right after ScheduleKeyDeletion,
    # so the follow-on read is retried rather than asserted once.
    described = _wait_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "PendingDeletion",
        timeout_s=60,
    )
    assert described["KeyState"] == "PendingDeletion", described["KeyState"]

    cancel_resp = kms.cancel_key_deletion(KeyId=key_id)
    # Real KMS echoes ONLY the key ARN here -- the new state must be read back.
    assert cancel_resp["KeyId"] == meta["Arn"], cancel_resp["KeyId"]
    assert "KeyState" not in cancel_resp, (
        f"CancelKeyDeletion must not return KeyState: {cancel_resp}"
    )

    described = _wait_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Disabled",
        timeout_s=60,
    )
    assert described["KeyState"] == "Disabled", described["KeyState"]
    assert "DeletionDate" not in described, described.get("DeletionDate")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
