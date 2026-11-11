"""update-primary-region-disabled-replica-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-primary-region-disabled-replica-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion onto a disabled replica is DisabledException "<arn> is disabled." and leaves
    the primary/replica roles unchanged; once the replica is enabled the same call moves the primary
    to the replica's Region."""
    primary_region = ctx.region
    # MultiRegion KMS keys need a genuine second AWS region to replicate into; any region
    # distinct from primary_region works, so this picks one of two fixed candidates rather
    # than deriving "some other region" from the target.
    replica_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"
    primary_kms = ctx.client("kms")
    replica_kms = ctx.client("kms", region=replica_region)

    created = primary_kms.create_key(
        MultiRegion=True,
        KeyUsage="ENCRYPT_DECRYPT",
        Description=ctx.unique_name("sim2real-mrk-disabled-promote-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]

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
        f"expected REPLICA after replicate_key, got {replica_meta['MultiRegionConfiguration']!r}"
    )

    replica_kms.disable_key(KeyId=key_id)
    disabled = _poll_until(
        lambda: replica_kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Disabled",
        timeout_s=60,
        interval_s=2,
    )
    assert disabled["KeyState"] == "Disabled", f"expected Disabled, got {disabled['KeyState']!r}"

    # break exactly one thing: try to promote the DISABLED replica to primary.
    err = _error(
        lambda: primary_kms.update_primary_region(KeyId=key_id, PrimaryRegion=replica_region)
    )
    assert err["Code"] == "DisabledException", f"expected DisabledException, got {err!r}"
    assert err["Message"] == f"{replica_meta['Arn']} is disabled.", err

    # effect absent: roles are completely unchanged on both sides.
    primary_after_reject = primary_kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert primary_after_reject["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY", (
        f"expected primary role unchanged (PRIMARY), got "
        f"{primary_after_reject['MultiRegionConfiguration']!r}"
    )
    assert (
        primary_after_reject["MultiRegionConfiguration"]["PrimaryKey"]["Region"] == primary_region
    ), (
        f"expected primary key region unchanged ({primary_region!r}), got "
        f"{primary_after_reject['MultiRegionConfiguration']['PrimaryKey']['Region']!r}"
    )
    replica_after_reject = replica_kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert replica_after_reject["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", (
        f"expected replica role unchanged (REPLICA), got "
        f"{replica_after_reject['MultiRegionConfiguration']!r}"
    )
    assert replica_after_reject["KeyState"] == "Disabled", (
        f"expected replica to remain Disabled (the rejected call must not re-enable it), got "
        f"{replica_after_reject['KeyState']!r}"
    )

    # positive control: remove the one blocking condition (re-enable the replica) and the exact
    # same call now succeeds, performing the real role swap.
    replica_kms.enable_key(KeyId=key_id)
    _poll_until(
        lambda: replica_kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        interval_s=2,
    )
    primary_kms.update_primary_region(KeyId=key_id, PrimaryRegion=replica_region)
    swapped = _poll_until(
        lambda: primary_kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA",
        timeout_s=90,
        interval_s=5,
    )
    assert swapped["MultiRegionConfiguration"]["PrimaryKey"]["Region"] == replica_region, (
        f"expected the restored call to swap primary to {replica_region!r}, got "
        f"{swapped['MultiRegionConfiguration']!r}"
    )


def _try_describe(client, key_id):
    try:
        return client.describe_key(KeyId=key_id)["KeyMetadata"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return None
        raise


def _error(fn):
    """The error (Code and Message) of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response["Error"]
        return {"Code": e.get("Code"), "Message": e.get("Message")}
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


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
