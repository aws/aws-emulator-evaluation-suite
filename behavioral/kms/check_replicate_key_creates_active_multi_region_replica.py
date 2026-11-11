"""replicate-key-creates-active-multi-region-replica."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "replicate-key-creates-active-multi-region-replica"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReplicateKey produces a replica in the target region that transitions
    Creating->Enabled, shares the primary's KeyId/key material (round-trips
    ciphertext across regions), and is visible via the primary's DescribeKey."""
    # Any region other than the primary's; multi-region replication requires a second real
    # physical region and there is no way to derive one from ctx.region.
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"

    primary = ctx.client("kms")
    resource_tags = [{"TagKey": "sim2real", "TagValue": "kms-replicate-key-creates-active-replica"}]

    primary_key_id = primary.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-behav-kms-mrk-"),
        Tags=resource_tags,
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: primary.schedule_key_deletion(KeyId=primary_key_id, PendingWindowInDays=7))

    primary_described = primary.describe_key(KeyId=primary_key_id)["KeyMetadata"]
    assert primary_described["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY", (
        primary_described["MultiRegionConfiguration"]
    )

    replica_meta = primary.replicate_key(
        KeyId=primary_key_id, ReplicaRegion=replica_region, Tags=resource_tags
    )["ReplicaKeyMetadata"]
    replica_arn = replica_meta["Arn"]
    assert replica_meta["KeyId"] == primary_key_id, (  # shared key ID across regions
        f"expected replica KeyId {primary_key_id!r}, got {replica_meta['KeyId']!r}"
    )

    replica_client = ctx.client("kms", region=replica_region)
    ctx.on_cleanup(lambda: replica_client.schedule_key_deletion(KeyId=replica_arn, PendingWindowInDays=7))

    replica_described = _poll_until(
        lambda: replica_client.describe_key(KeyId=replica_arn)["KeyMetadata"],
        lambda d: d["KeyState"] not in ("Creating",),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert replica_described["KeyState"] == "Enabled", replica_described["KeyState"]
    assert replica_described["KeyId"] == primary_key_id, (
        f"expected replica KeyId {primary_key_id!r}, got {replica_described['KeyId']!r}"
    )
    assert replica_described["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", (
        replica_described["MultiRegionConfiguration"]
    )

    # The primary's own view lists the new replica region.
    primary_view = _poll_until(
        lambda: primary.describe_key(KeyId=primary_key_id)["KeyMetadata"],
        lambda d: any(
            r["Region"] == replica_region
            for r in d["MultiRegionConfiguration"].get("ReplicaKeys", [])
        ),
        timeout_s=60.0,
        interval_s=3.0,
    )
    replica_regions = [r["Region"] for r in primary_view["MultiRegionConfiguration"]["ReplicaKeys"]]
    assert replica_region in replica_regions, replica_regions

    # Shared key material: encrypt in the primary region, decrypt via the replica.
    plaintext = b"sim2real-multi-region-shared-material"
    ciphertext = primary.encrypt(KeyId=primary_key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = replica_client.decrypt(KeyId=replica_arn, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, (
        f"replica in {replica_region} could not decrypt ciphertext its primary produced — "
        f"expected {plaintext!r}, got {decrypted!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
