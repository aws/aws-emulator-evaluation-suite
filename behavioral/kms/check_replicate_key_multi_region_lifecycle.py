"""replicate-key-multi-region-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "replicate-key-multi-region-lifecycle"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplicateKey creates a replica with the primary's KeyId and its own ARN that becomes Enabled
    as type REPLICA; scheduling its deletion moves it to PendingDeletion and leaves the primary
    Enabled."""
    region_a = ctx.region
    region_b = _alt_region(region_a)
    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)

    primary = kms_a.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-mrk-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = primary["KeyMetadata"]["KeyId"]
    primary_arn = primary["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_a, key_id))
    assert primary["KeyMetadata"]["MultiRegion"] is True, primary["KeyMetadata"]

    replicated = kms_a.replicate_key(
        KeyId=key_id,
        ReplicaRegion=region_b,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    replica_meta = replicated["ReplicaKeyMetadata"]
    assert replica_meta["KeyId"] == key_id, replica_meta
    replica_arn = replica_meta["Arn"]
    assert replica_arn != primary_arn, (replica_arn, primary_arn)
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_b, key_id))

    def _replica_enabled() -> dict[str, Any] | None:
        d = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    replica_desc = _poll_until(_replica_enabled, timeout_s=300.0, interval_s=5.0)
    assert replica_desc is not None, "replica key never reached Enabled"
    mrc = replica_desc["MultiRegionConfiguration"]
    assert mrc["MultiRegionKeyType"] == "REPLICA", mrc
    assert mrc["PrimaryKey"]["Arn"] == primary_arn, mrc["PrimaryKey"]

    kms_b.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)

    def _replica_pending_deletion() -> dict[str, Any] | None:
        d = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "PendingDeletion" else None

    pending = _poll_until(_replica_pending_deletion, timeout_s=30.0, interval_s=2.0)
    assert pending is not None, "replica never reached PendingDeletion"
    assert "DeletionDate" in pending, pending

    primary_desc = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]
    assert primary_desc["KeyState"] == "Enabled", primary_desc["KeyState"]


def _alt_region(region: str) -> str:
    """Pick a deterministic ReplicateKey target Region other than region."""
    return "us-west-2" if region != "us-west-2" else "us-east-1"


def _safe_schedule_delete(client: Any, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(
    probe: Callable[[], Any], *, timeout_s: float, interval_s: float = 1.0
) -> Any | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
