"""describe-key."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "describe-key"
GROUP = 'key_lifecycle'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeKey returns consistent, correctly-shaped metadata for a created key."""
    kms = ctx.client("kms")
    created = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-describe-key"}],
    )["KeyMetadata"]
    key_id = created["KeyId"]

    def _cleanup_key(_k=key_id):
        state = kms.describe_key(KeyId=_k)["KeyMetadata"]["KeyState"]
        if state != "PendingDeletion":
            kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7)

    ctx.on_cleanup(_cleanup_key)

    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyId"] == key_id, f"expected KeyId {key_id!r}, got {meta['KeyId']!r}"
    assert meta["Arn"] == created["Arn"], f"expected Arn {created['Arn']!r}, got {meta['Arn']!r}"
    assert meta["KeyState"] == "Enabled", f"expected KeyState Enabled, got {meta['KeyState']!r}"
    assert meta["KeyUsage"] == "ENCRYPT_DECRYPT", f"expected KeyUsage ENCRYPT_DECRYPT, got {meta['KeyUsage']!r}"
    assert meta["KeySpec"] == "SYMMETRIC_DEFAULT", f"expected KeySpec SYMMETRIC_DEFAULT, got {meta['KeySpec']!r}"
    assert meta["Origin"] == "AWS_KMS", f"expected Origin AWS_KMS, got {meta['Origin']!r}"
    assert meta["KeyManager"] == "CUSTOMER", f"expected KeyManager CUSTOMER, got {meta['KeyManager']!r}"
    assert meta["MultiRegion"] is False, f"expected MultiRegion False, got {meta['MultiRegion']!r}"

    creation_date = meta["CreationDate"]
    assert isinstance(creation_date, datetime), f"expected CreationDate to be a real timestamp, got {creation_date!r}"
    age = datetime.now(timezone.utc) - creation_date
    assert timedelta(0) <= age < timedelta(minutes=10), f"expected CreationDate within the last 10 minutes, age was {age}"

    # Independent read at the destination confirming the mutation, not the create call's own response.
    kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    deadline = time.monotonic() + 15
    post = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    while "DeletionDate" not in post and time.monotonic() < deadline:
        time.sleep(2)
        post = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert post["KeyState"] == "PendingDeletion", f"expected KeyState PendingDeletion after scheduling, got {post['KeyState']!r}"
    assert "DeletionDate" in post, f"expected DeletionDate within 15s of scheduling deletion, never appeared; last read: {post!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
