"""update-primary-region-disabled-key-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-primary-region-disabled-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]

_CANDIDATE_REGIONS = ["us-west-2", "us-east-1", "eu-west-1"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion swaps an enabled primary and replica, but with the current primary disabled
    it is DisabledException "<arn> is disabled." and the roles stay unchanged; after re-enabling, the
    same promotion succeeds and swaps the roles."""
    replica_region = _one_other_region(ctx)

    origin_client = ctx.client("kms")
    key_id = origin_client.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-kms-upr-disabled-"),
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: origin_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    replica_arn = origin_client.replicate_key(KeyId=key_id, ReplicaRegion=replica_region)[
        "ReplicaKeyMetadata"
    ]["Arn"]
    replica_client = ctx.client("kms", region=replica_region)
    ctx.on_cleanup(
        lambda: replica_client.schedule_key_deletion(KeyId=replica_arn, PendingWindowInDays=7)
    )
    _poll_until(
        lambda: replica_client.describe_key(KeyId=replica_arn)["KeyMetadata"],
        lambda d: d["KeyState"] == "Enabled",
        timeout_s=90.0,
        interval_s=3.0,
    )

    # Positive control: while ENABLED, UpdatePrimaryRegion really does promote
    # the replica and demote the original primary.
    origin_client.update_primary_region(KeyId=key_id, PrimaryRegion=replica_region)
    demoted = _poll_until(
        lambda: origin_client.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert demoted["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", (
        f"expected origin key demoted to REPLICA after promotion, got "
        f"{demoted['MultiRegionConfiguration']['MultiRegionKeyType']}"
    )
    promoted = _poll_until(
        lambda: replica_client.describe_key(KeyId=replica_arn)["KeyMetadata"],
        lambda d: d["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert promoted["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY", (
        f"expected replica promoted to PRIMARY, got "
        f"{promoted['MultiRegionConfiguration']['MultiRegionKeyType']}"
    )

    # Break exactly one thing: disable the (now) primary key, in its own region.
    replica_client.disable_key(KeyId=replica_arn)
    disabled_described = replica_client.describe_key(KeyId=replica_arn)["KeyMetadata"]
    assert disabled_described["KeyState"] == "Disabled", disabled_described["KeyState"]

    # The origin region already holds a REPLICA of this key set, so
    # PrimaryRegion=origin satisfies UpdatePrimaryRegion's "target already has a
    # replica" precondition -- isolating DisabledException as the sole cause.
    err = _error(
        lambda: replica_client.update_primary_region(KeyId=replica_arn, PrimaryRegion=ctx.region)
    )
    assert err["Code"] == "DisabledException", err
    assert err["Message"] == f"{replica_arn} is disabled.", err

    # Effect absent: primary status never moved back to the origin region.
    still_replica = origin_client.describe_key(KeyId=key_id)["KeyMetadata"]
    assert still_replica["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", (
        f"expected origin key to remain REPLICA after the rejected call, got "
        f"{still_replica['MultiRegionConfiguration']['MultiRegionKeyType']}"
    )
    still_primary = replica_client.describe_key(KeyId=replica_arn)["KeyMetadata"]
    assert still_primary["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY", (
        f"expected disabled key to remain PRIMARY after the rejected call, got "
        f"{still_primary['MultiRegionConfiguration']['MultiRegionKeyType']}"
    )
    assert still_primary["KeyState"] == "Disabled", (
        f"expected key to remain Disabled after the rejected call, got {still_primary['KeyState']}"
    )

    # Restore: re-enable the primary, then the identical promotion succeeds.
    replica_client.enable_key(KeyId=replica_arn)
    _poll_until(
        lambda: replica_client.describe_key(KeyId=replica_arn)["KeyMetadata"],
        lambda d: d["KeyState"] == "Enabled",
        timeout_s=30.0,
        interval_s=2.0,
    )
    replica_client.update_primary_region(KeyId=replica_arn, PrimaryRegion=ctx.region)
    restored_primary = _poll_until(
        lambda: origin_client.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert restored_primary["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY", (
        f"expected origin key re-promoted to PRIMARY after restore, got "
        f"{restored_primary['MultiRegionConfiguration']['MultiRegionKeyType']}"
    )
    restored_replica = _poll_until(
        lambda: replica_client.describe_key(KeyId=replica_arn)["KeyMetadata"],
        lambda d: d["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert restored_replica["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", (
        f"expected the now-re-enabled key demoted to REPLICA after restore, got "
        f"{restored_replica['MultiRegionConfiguration']['MultiRegionKeyType']}"
    )


def _one_other_region(ctx) -> str:
    for region in _CANDIDATE_REGIONS:
        if region != ctx.region:
            return region
    raise AssertionError("no candidate region distinct from ctx.region")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """The error (Code and Message) of a call real AWS refuses; an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return {"Code": e.get("Code"), "Message": e.get("Message")}
    raise AssertionError(f"expected rejection but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
