"""e2e-multi-region-replica-failover."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-multi-region-replica-failover"
GROUP = "e2e"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Primary ciphertext decrypts on a multi-Region replica; after UpdatePrimaryRegion swaps the
    roles, the original ciphertext still decrypts on the new primary and new-primary ciphertext
    decrypts on the old primary (shared key material)."""
    primary_region = ctx.region
    # ReplicateKey needs a distinct real Region; no API names "some other Region".
    replica_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"
    primary_kms = ctx.client("kms")
    replica_kms = ctx.client("kms", region=replica_region)

    created = primary_kms.create_key(
        MultiRegion=True,
        KeyUsage="ENCRYPT_DECRYPT",
        Description=ctx.unique_name("sim2real-mrk-failover-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    assert created["KeyMetadata"]["MultiRegion"] is True, (
        f"CreateKey(MultiRegion=True) did not create a multi-Region key: "
        f"MultiRegion={created['KeyMetadata']['MultiRegion']!r}"
    )

    def _cleanup() -> None:
        for region_client in (primary_kms, replica_kms):
            try:
                region_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    primary_kms.replicate_key(KeyId=key_id, ReplicaRegion=replica_region)

    replica_meta = _poll_until(
        lambda: _try_describe(replica_kms, key_id),
        lambda m: m is not None and m["KeyState"] == "Enabled",
        timeout_s=180,
        interval_s=10,
    )
    assert replica_meta["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", (
        f"replica endpoint reports MultiRegionKeyType="
        f"{replica_meta['MultiRegionConfiguration']['MultiRegionKeyType']!r}, expected 'REPLICA'"
    )
    assert replica_meta["MultiRegionConfiguration"]["PrimaryKey"]["Region"] == primary_region, (
        f"replica's PrimaryKey.Region={replica_meta['MultiRegionConfiguration']['PrimaryKey']['Region']!r}, "
        f"expected the original primary Region {primary_region!r}"
    )

    plaintext = b"sim2real-kms-cross-region-failover-payload"
    ciphertext_from_primary = primary_kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted_on_replica = replica_kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext_from_primary)[
        "Plaintext"
    ]
    assert decrypted_on_replica == plaintext, (
        "replica endpoint could not decrypt ciphertext the primary produced -- shared key "
        "material did not carry across ReplicateKey"
    )

    primary_kms.update_primary_region(KeyId=key_id, PrimaryRegion=replica_region)

    swapped = _poll_until(
        lambda: primary_kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled"
        and m["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA",
        timeout_s=90,
        interval_s=5,
    )
    assert swapped["MultiRegionConfiguration"]["PrimaryKey"]["Region"] == replica_region, (
        f"original-primary endpoint reports PrimaryKey.Region="
        f"{swapped['MultiRegionConfiguration']['PrimaryKey']['Region']!r} after UpdatePrimaryRegion, "
        f"expected the promoted Region {replica_region!r}"
    )

    decrypted_after_promotion = replica_kms.decrypt(
        KeyId=key_id, CiphertextBlob=ciphertext_from_primary
    )["Plaintext"]
    assert decrypted_after_promotion == plaintext, (
        "now-primary replica endpoint could not decrypt the pre-promotion ciphertext -- "
        "UpdatePrimaryRegion disturbed the underlying key material instead of only swapping roles"
    )

    ciphertext_from_new_primary = replica_kms.encrypt(KeyId=key_id, Plaintext=plaintext)[
        "CiphertextBlob"
    ]
    decrypted_on_old_primary = primary_kms.decrypt(
        KeyId=key_id, CiphertextBlob=ciphertext_from_new_primary
    )["Plaintext"]
    assert decrypted_on_old_primary == plaintext, (
        "now-replica original endpoint could not decrypt a ciphertext the newly-promoted primary "
        "just produced -- the promoted key is not genuinely usable at the new primary"
    )


def _try_describe(client, key_id):
    """DescribeKey, or None while the key has not yet propagated to this endpoint."""
    try:
        return client.describe_key(KeyId=key_id)["KeyMetadata"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return None
        raise


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
