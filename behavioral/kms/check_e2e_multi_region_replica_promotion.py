"""e2e-multi-region-replica-promotion."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-multi-region-replica-promotion"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Ciphertext produced by the original multi-Region primary remains decryptable by the
    replica both immediately after ReplicateKey and after UpdatePrimaryRegion promotes that
    replica -- proving cross-region key material equivalence survives the promotion."""
    primary = ctx.client("kms")
    # A multi-Region replica must land in a second, real region distinct from ctx.region --
    # us-west-2 (or us-east-1, when the run's own region already is us-west-2) is the fixed pair
    # used corpus-wide for this purpose, not a stand-in for ctx.region.
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    replica = ctx.client("kms", region=replica_region)

    created = primary.create_key(
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        MultiRegion=True,
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-e2e-multi-region-replica-promotion"}],
    )
    primary_key_id = created["KeyMetadata"]["KeyId"]
    primary_arn = created["KeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: primary.schedule_key_deletion(KeyId=primary_key_id, PendingWindowInDays=7))
    )

    plaintext_before = b"sim2real-pre-replication-payload"
    ciphertext_before = primary.encrypt(KeyId=primary_key_id, Plaintext=plaintext_before)["CiphertextBlob"]

    rep = primary.replicate_key(KeyId=primary_key_id, ReplicaRegion=replica_region)
    replica_arn = rep["ReplicaKeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: replica.schedule_key_deletion(KeyId=replica_arn, PendingWindowInDays=7))
    )
    _poll_until(
        lambda: replica.describe_key(KeyId=replica_arn)["KeyMetadata"]["KeyState"],
        lambda s: s == "Enabled",
        timeout_s=300,
        interval_s=5,
    )

    # ciphertext produced before the replica even existed still decrypts on the replica side
    decrypted = replica.decrypt(KeyId=replica_arn, CiphertextBlob=ciphertext_before)["Plaintext"]
    assert decrypted == plaintext_before, (
        f"replica {replica_arn} decrypted pre-replication ciphertext to {decrypted!r}, "
        f"expected {plaintext_before!r}"
    )

    primary.update_primary_region(KeyId=primary_key_id, PrimaryRegion=replica_region)
    _poll_until(
        lambda: replica.describe_key(KeyId=replica_arn)["KeyMetadata"]["MultiRegionConfiguration"],
        lambda mrc: mrc["MultiRegionKeyType"] == "PRIMARY",
        timeout_s=120,
        interval_s=5,
    )

    # the pre-promotion ciphertext still decrypts on the now-demoted original key
    demoted_decrypt = primary.decrypt(KeyId=primary_arn, CiphertextBlob=ciphertext_before)["Plaintext"]
    assert demoted_decrypt == plaintext_before, (
        f"demoted original key {primary_arn} decrypted pre-promotion ciphertext to "
        f"{demoted_decrypt!r}, expected {plaintext_before!r}"
    )

    # a fresh ciphertext from the newly-promoted primary decrypts on the now-replica original
    plaintext_after = b"sim2real-post-promotion-payload"
    ciphertext_after = replica.encrypt(KeyId=replica_arn, Plaintext=plaintext_after)["CiphertextBlob"]
    post_promotion_decrypt = primary.decrypt(KeyId=primary_arn, CiphertextBlob=ciphertext_after)["Plaintext"]
    assert post_promotion_decrypt == plaintext_after, (
        f"demoted original key {primary_arn} decrypted post-promotion ciphertext to "
        f"{post_promotion_decrypt!r}, expected {plaintext_after!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
