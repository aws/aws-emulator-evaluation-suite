"""update-primary-region-on-replica-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-primary-region-on-replica-rejected"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion called against a REPLICA key is rejected with
    KMSInvalidStateException, and the identical call issued from the true primary succeeds
    (positive control) against the same multi-Region key set."""
    primary = ctx.client("kms")
    replica_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    replica = ctx.client("kms", region=replica_region)

    created = primary.create_key(
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        MultiRegion=True,
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    primary_key_id = created["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: primary.schedule_key_deletion(KeyId=primary_key_id, PendingWindowInDays=7))
    )

    rep = primary.replicate_key(
        KeyId=primary_key_id,
        ReplicaRegion=replica_region,
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
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

    # negative: the replica cannot promote itself to primary via its own KeyId
    refused = _error(
        lambda: replica.update_primary_region(KeyId=replica_arn, PrimaryRegion=replica_region)
    )
    expected = ("KMSInvalidStateException", f"{replica_arn} is not a multi-Region primary key.")
    assert refused == expected, f"expected {expected!r}, got {refused!r}"
    # effect absent: still a replica, primary designation unchanged
    unchanged = replica.describe_key(KeyId=replica_arn)["KeyMetadata"]["MultiRegionConfiguration"]
    assert unchanged["MultiRegionKeyType"] == "REPLICA", (
        f"expected MultiRegionKeyType=REPLICA (unchanged), got {unchanged['MultiRegionKeyType']!r}"
    )
    assert unchanged["PrimaryKey"]["Region"] == ctx.region, (
        f"expected PrimaryKey.Region={ctx.region!r} (unchanged), "
        f"got {unchanged['PrimaryKey']['Region']!r}"
    )

    # positive control: the real primary can flip the designation
    primary.update_primary_region(KeyId=primary_key_id, PrimaryRegion=replica_region)
    flipped = _poll_until(
        lambda: replica.describe_key(KeyId=replica_arn)["KeyMetadata"]["MultiRegionConfiguration"],
        lambda mrc: mrc["MultiRegionKeyType"] == "PRIMARY",
        timeout_s=120,
        interval_s=5,
    )
    assert flipped["PrimaryKey"]["Region"] == replica_region, (
        f"expected PrimaryKey.Region={replica_region!r} after promotion, "
        f"got {flipped['PrimaryKey']['Region']!r}"
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


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success is a defect."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(
        f"expected update_primary_region on a replica key to raise, but it succeeded "
        f"and returned {result!r}"
    )


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
