"""multi-region-replica-independent-deletion."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "multi-region-replica-independent-deletion"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scheduling deletion of a multi-Region REPLICA key leaves the primary key's KeyState and
    cryptographic usability entirely unaffected — the primary keeps encrypting/decrypting fine
    both before and after the replica is marked PendingDeletion."""
    region_a = ctx.region
    region_b = _alt_region(region_a)
    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)

    primary = kms_a.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-mrkd-"),
        Tags=[{"TagKey": "sim2real", "TagValue": ctx.unique_name("mrkd-")}],
    )
    key_id = primary["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_a, key_id))

    kms_a.replicate_key(KeyId=key_id, ReplicaRegion=region_b)
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_b, key_id))

    def _replica_enabled() -> dict[str, Any] | None:
        d = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    replica_enabled = _poll_until(_replica_enabled, timeout_s=300.0, interval_s=5.0)
    assert replica_enabled is not None, "replica never reached Enabled"

    # Positive control BEFORE the replica is touched: primary is usable.
    plaintext = b"sim2real-primary-still-usable"
    ciphertext_before = kms_a.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted_before = kms_a.decrypt(CiphertextBlob=ciphertext_before, KeyId=key_id)["Plaintext"]
    assert decrypted_before == plaintext, f"expected {plaintext!r}, got {decrypted_before!r}"

    kms_b.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)

    def _replica_pending_deletion() -> dict[str, Any] | None:
        d = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "PendingDeletion" else None

    replica_pending = _poll_until(_replica_pending_deletion, timeout_s=30.0, interval_s=2.0)
    assert replica_pending is not None, "replica never reached PendingDeletion"

    # Primary's KeyState must remain Enabled...
    primary_desc = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]
    assert primary_desc["KeyState"] == "Enabled", (
        f"expected primary KeyState Enabled after replica deletion was scheduled, "
        f"got {primary_desc['KeyState']!r}"
    )
    # ...and it must still be cryptographically usable: fresh Encrypt/Decrypt, plus decrypting
    # the ciphertext produced before the replica's deletion was ever scheduled.
    ciphertext_after = kms_a.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted_after = kms_a.decrypt(CiphertextBlob=ciphertext_after, KeyId=key_id)["Plaintext"]
    assert decrypted_after == plaintext, f"expected {plaintext!r}, got {decrypted_after!r}"
    decrypted_old = kms_a.decrypt(CiphertextBlob=ciphertext_before, KeyId=key_id)["Plaintext"]
    assert decrypted_old == plaintext, (
        f"primary could not decrypt pre-existing ciphertext after replica deletion was "
        f"scheduled: expected {plaintext!r}, got {decrypted_old!r}"
    )


def _alt_region(region: str) -> str:
    # Multi-Region KMS replication needs a second, concrete AWS region distinct from ctx.region —
    # there is no "any other region" the API will accept, so a literal partner region is required.
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
