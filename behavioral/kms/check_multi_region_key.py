"""multi-region-key."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "multi-region-key"
GROUP = 'multi_region'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating a multi-region key produces a real MRK primary: an independent
    DescribeKey read (not the create response) confirms MultiRegionKeyType
    PRIMARY, an empty replica list, and an Enabled key state."""
    kms = ctx.client("kms")
    desc = f"sim2real-behav-key-mrk-{uuid.uuid4().hex[:8]}"
    created = kms.create_key(
        Description=desc,
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        MultiRegion=True,
    )["KeyMetadata"]
    key_id = created["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    assert key_id.startswith("mrk-"), f"expected mrk- prefixed key id, got {key_id!r}"

    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    mrc = described["MultiRegionConfiguration"]
    assert mrc["MultiRegionKeyType"] == "PRIMARY", f"expected PRIMARY, got {mrc!r}"
    assert mrc.get("ReplicaKeys", []) == [], f"expected no replicas yet, got {mrc['ReplicaKeys']!r}"
    assert described["KeyState"] == "Enabled", f"expected Enabled, got {described['KeyState']!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
