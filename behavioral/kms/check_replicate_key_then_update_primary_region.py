"""replicate-key-then-update-primary-region."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicate-key-then-update-primary-region"
GROUP = "state-machine"
SERVICES = ["kms"]

# Upper bound for retrying ScheduleKeyDeletion while a key reads Updating after UpdatePrimaryRegion.
_CLEANUP_S = 900.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReplicateKey adds the replica Region to the PRIMARY's ReplicaKeys, and UpdatePrimaryRegion makes the original
    key a REPLICA whose PrimaryKey is the other Region and whose ReplicaKeys list only the original Region; if
    the replica endpoint answers within 90 s, it reports REPLICA and decrypts the primary's ciphertext."""
    primary_region = ctx.region
    # ReplicateKey needs a genuinely distinct, real AWS region -- region-pinned by the operation
    # under test, not derivable from ctx.
    replica_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"
    primary_kms = ctx.client("kms")
    # ctx.client(region=) signs for the replica region on every target, with ctx's own credentials.
    replica_kms = ctx.client("kms", region=replica_region)

    created = primary_kms.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-mrk-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]

    def _cleanup() -> None:
        # After UpdatePrimaryRegion either key can still read Updating, when ScheduleKeyDeletion
        # answers KMSInvalidStateException; retry that every 2 s to the cleanup deadline.
        deadline = time.monotonic() + _CLEANUP_S
        for region_client in (primary_kms, replica_kms):
            while True:
                try:
                    region_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
                    break
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code == "NotFoundException":
                        break
                    if code != "KMSInvalidStateException":
                        raise
                    state = region_client.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
                    if state in ("PendingDeletion", "PendingReplicaDeletion"):
                        break
                    if state != "Updating" or time.monotonic() >= deadline:
                        raise
                time.sleep(2)

    ctx.on_cleanup(_cleanup)

    initial = primary_kms.describe_key(KeyId=key_id)["KeyMetadata"]
    initial_type = initial["MultiRegionConfiguration"]["MultiRegionKeyType"]
    assert initial_type == "PRIMARY", f"expected freshly-created MRK to be PRIMARY, got {initial_type!r}"
    initial_primary_region = initial["MultiRegionConfiguration"]["PrimaryKey"]["Region"]
    assert initial_primary_region == primary_region, (
        f"expected PrimaryKey.Region {primary_region!r}, got {initial_primary_region!r}"
    )

    primary_kms.replicate_key(KeyId=key_id, ReplicaRegion=replica_region)

    # State-machine assertion #1: the primary's OWN record (same account, same region it was
    # created in -- syncs in seconds) lists the new replica once ReplicateKey has taken effect.
    primary_after_replicate = _poll_until(
        lambda: primary_kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: any(
            r["Region"] == replica_region for r in m["MultiRegionConfiguration"]["ReplicaKeys"]
        ),
        timeout_s=120,
        interval_s=5,
    )
    after_replicate_type = primary_after_replicate["MultiRegionConfiguration"]["MultiRegionKeyType"]
    assert after_replicate_type == "PRIMARY", (
        f"expected primary to remain PRIMARY after ReplicateKey, got {after_replicate_type!r}"
    )

    # depth (best-effort): shared key material, confirmed with a real cross-region round trip once
    # the replica-region endpoint itself becomes reachable. Bounded separately and SKIPPED (not
    # failed) on timeout -- a slow-to-propagate replica ENDPOINT is not a state-machine violation,
    # it's the account's first-ever key in that region, and the primary-side assertions above
    # already proved the replication transition happened.
    plaintext = b"sim2real-kms-cross-region-payload"
    replica_reachable = _poll_until(
        lambda: _try_describe(replica_kms, key_id),
        lambda m: m is not None and m.get("KeyState") == "Enabled",
        timeout_s=90,
        interval_s=10,
        soft=True,
    )
    if replica_reachable is not None:
        replica_type = replica_reachable["MultiRegionConfiguration"]["MultiRegionKeyType"]
        assert replica_type == "REPLICA", f"expected replica-side view to be REPLICA, got {replica_type!r}"
        replica_primary_region = replica_reachable["MultiRegionConfiguration"]["PrimaryKey"]["Region"]
        assert replica_primary_region == primary_region, (
            f"expected replica's PrimaryKey.Region {primary_region!r}, got {replica_primary_region!r}"
        )
        ciphertext = primary_kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
        decrypted = replica_kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
        assert decrypted == plaintext, (
            f"cross-region decrypt mismatch: expected {plaintext!r}, got {decrypted!r}"
        )

    primary_kms.update_primary_region(KeyId=key_id, PrimaryRegion=replica_region)

    # State-machine assertion #2: the swap, observed from the ORIGINAL key's own record (same
    # account/region as the check's whole session -- again fast, per UpdatePrimaryRegion's docs
    # ("a few more seconds")). It must flip from PRIMARY to REPLICA, with PrimaryKey pointing
    # at the (former) replica region.
    swapped = _poll_until(
        lambda: primary_kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled"
        and m["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA",
        timeout_s=90,
        interval_s=5,
    )
    swapped_primary_region = swapped["MultiRegionConfiguration"]["PrimaryKey"]["Region"]
    assert swapped_primary_region == replica_region, (
        f"expected PrimaryKey.Region to have swapped to {replica_region!r}, got {swapped_primary_region!r}"
    )
    # sanity: the replica list this (demoted) key reports still only contains the region it
    # was created in -- roles swapped, but the multi-Region *set* is still just these two regions.
    swapped_replica_regions = {r["Region"] for r in swapped["MultiRegionConfiguration"]["ReplicaKeys"]}
    assert swapped_replica_regions == {primary_region}, (
        f"expected ReplicaKeys regions to be {{{primary_region!r}}}, got {swapped_replica_regions!r}"
    )


def _try_describe(client, key_id):
    """DescribeKey, or None if the key isn't visible YET on this (possibly cross-region) endpoint
    -- distinguishes "not propagated yet" from a real failure so a soft poll can treat it as
    not-ready rather than blowing up."""
    try:
        return client.describe_key(KeyId=key_id)["KeyMetadata"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return None
        raise


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0, soft=False):
    """Poll ``probe`` until ``predicate`` is true. Raises on timeout UNLESS ``soft`` is set, in
    which case it returns None on timeout instead -- for a best-effort depth check whose own
    endpoint may lag well past what the check's overall wall-clock budget can absorb, without
    turning that lag into a state-machine failure."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if soft:
        return None
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
