"""update-primary-region-promotes-replica."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-primary-region-promotes-replica"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion promotes a replica to PRIMARY and demotes the former
    primary to REPLICA, verified on both sides via DescribeKey's
    MultiRegionConfiguration."""
    # MRK replication requires a concrete, distinct AWS Region for the replica -- there is no
    # relative "other region" request shape, so a literal alternate Region is unavoidable here.
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"

    original_primary_client = ctx.client("kms")
    original_key = original_primary_client.create_key(MultiRegion=True)["KeyMetadata"]
    key_id = original_key["KeyId"]
    key_arn = original_key["Arn"]
    ctx.on_cleanup(
        lambda: original_primary_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )

    replica_arn = original_primary_client.replicate_key(KeyId=key_id, ReplicaRegion=replica_region)[
        "ReplicaKeyMetadata"
    ]["Arn"]
    replica_client = ctx.client("kms", region=replica_region)
    ctx.on_cleanup(
        lambda: replica_client.schedule_key_deletion(KeyId=replica_arn, PendingWindowInDays=7)
    )

    # Both the primary and the replica must be Enabled before UpdatePrimaryRegion.
    _poll_until(
        lambda: replica_client.describe_key(KeyId=replica_arn)["KeyMetadata"],
        lambda d: d["KeyState"] == "Enabled",
        timeout_s=90.0,
        interval_s=3.0,
    )

    original_primary_client.update_primary_region(KeyId=key_id, PrimaryRegion=replica_region)

    demoted = _poll_until(
        lambda: original_primary_client.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert demoted["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", demoted[
        "MultiRegionConfiguration"
    ]
    demoted_primary_key = demoted["MultiRegionConfiguration"]["PrimaryKey"]
    assert demoted_primary_key["Region"] == replica_region, (
        f"expected demoted key's PrimaryKey.Region == {replica_region!r}, got "
        f"{demoted_primary_key['Region']!r}"
    )
    assert demoted_primary_key["Arn"] == replica_arn, (
        f"expected demoted key's PrimaryKey.Arn == {replica_arn!r} (the promoted replica), got "
        f"{demoted_primary_key['Arn']!r}"
    )

    # Propagation of the promotion to the (new-primary) replica region can lag
    # behind the update call itself, so poll until it actually reaches PRIMARY
    # rather than merely leaving the transient "Updating" state.
    promoted = _poll_until(
        lambda: replica_client.describe_key(KeyId=replica_arn)["KeyMetadata"],
        lambda d: d["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert promoted["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY", promoted[
        "MultiRegionConfiguration"
    ]
    promoted_primary_key = promoted["MultiRegionConfiguration"]["PrimaryKey"]
    assert promoted_primary_key["Region"] == replica_region, (
        f"expected promoted key's own PrimaryKey.Region == {replica_region!r}, got "
        f"{promoted_primary_key['Region']!r}"
    )
    promoted_replica_arns = {rk["Arn"] for rk in promoted["MultiRegionConfiguration"]["ReplicaKeys"]}
    assert key_arn in promoted_replica_arns, (
        f"expected the demoted original key {key_arn!r} to appear in the promoted primary's "
        f"ReplicaKeys, got {promoted_replica_arns!r}"
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
