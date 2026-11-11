"""create-symmetric-key."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-symmetric-key"
GROUP = 'key_lifecycle'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKey (symmetric) returns valid KeyMetadata, confirmed by an independent DescribeKey."""
    kms = ctx.client("kms")
    desc = f"sim2real-behav-key-sym-create-{uuid.uuid4().hex[:8]}"
    resp = kms.create_key(
        Description=desc,
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    created = resp["KeyMetadata"]
    key_id = created["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    assert "KeyId" in created, f"expected CreateKey response to carry KeyId, got keys {sorted(created)}"
    assert "Arn" in created, f"expected CreateKey response to carry Arn, got keys {sorted(created)}"

    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyId"] == key_id, f"expected DescribeKey to echo KeyId {key_id!r}, got {meta['KeyId']!r}"
    assert meta["KeyState"] == "Enabled", f"expected KeyState Enabled, got {meta['KeyState']!r}"
    assert meta["KeyUsage"] == "ENCRYPT_DECRYPT", f"expected KeyUsage ENCRYPT_DECRYPT, got {meta['KeyUsage']!r}"
    assert meta["KeySpec"] == "SYMMETRIC_DEFAULT", f"expected KeySpec SYMMETRIC_DEFAULT, got {meta['KeySpec']!r}"
    assert meta["Description"] == desc, f"expected Description {desc!r}, got {meta['Description']!r}"
    assert meta["Enabled"] is True, f"expected Enabled True, got {meta['Enabled']!r}"
    assert meta["KeyManager"] == "CUSTOMER", f"expected KeyManager CUSTOMER, got {meta['KeyManager']!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
