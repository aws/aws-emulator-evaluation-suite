"""schedule-key-deletion."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "schedule-key-deletion"
GROUP = 'key_lifecycle'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ScheduleKeyDeletion transitions key to PendingDeletion and computes DeletionDate PendingWindowInDays out.

    DescribeKey's own DeletionDate lags KeyState by a few seconds after ScheduleKeyDeletion
    (confirmed against real AWS), so it is polled rather than read once.
    """
    kms = ctx.client("kms")
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    before = datetime.now(timezone.utc)
    resp = kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    assert "DeletionDate" in resp, f"expected DeletionDate in ScheduleKeyDeletion response, got keys {sorted(resp)}"
    deletion_date = resp["DeletionDate"]
    expected = before + timedelta(days=7)
    drift_s = abs((deletion_date - expected).total_seconds())
    assert drift_s < 600, (
        f"expected DeletionDate ~7 days out ({expected.isoformat()}), "
        f"got {deletion_date.isoformat()} (drift {drift_s:.0f}s)"
    )

    meta = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        if "DeletionDate" in meta:
            break
        time.sleep(2)
    assert meta["KeyState"] == "PendingDeletion", f"expected KeyState PendingDeletion, got {meta.get('KeyState')}"
    assert "DeletionDate" in meta, "DescribeKey never surfaced DeletionDate for a PendingDeletion key within 30s"
    assert meta["DeletionDate"] == deletion_date, (
        f"expected DescribeKey DeletionDate to match ScheduleKeyDeletion response ({deletion_date.isoformat()}), "
        f"got {meta['DeletionDate'].isoformat()}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
