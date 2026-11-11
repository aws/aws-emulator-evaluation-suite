"""replicate-key-disabled-account-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "replicate-key-disabled-account-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ReplicateKey against a disabled multi-Region primary key returns DisabledException."""
    kms = ctx.client("kms")
    replica_region = _pick_other_region(ctx.region)

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-mrk-"),
        MultiRegion=True,
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))

    kms.disable_key(KeyId=key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Disabled",
        timeout_s=30.0,
        interval_s=2.0,
    )

    code, message = _error(lambda: kms.replicate_key(KeyId=key_id, ReplicaRegion=replica_region))
    assert code == "DisabledException", f"expected DisabledException, got {code}"
    assert message == f"{key_arn} is disabled.", message

    cfg = kms.describe_key(KeyId=key_id)["KeyMetadata"].get("MultiRegionConfiguration", {})
    replicas = cfg.get("ReplicaKeys", []) if cfg else []
    assert not any(r["Region"] == replica_region for r in replicas), (
        "no replica should have been created while the primary key was disabled"
    )

    # positive control: re-enabling the key allows the identical replication to succeed
    kms.enable_key(KeyId=key_id)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Enabled",
        timeout_s=30.0,
        interval_s=2.0,
    )
    second = kms.replicate_key(KeyId=key_id, ReplicaRegion=replica_region)
    ctx.on_cleanup(lambda: _safe_cleanup_replica(ctx, replica_region, key_id))
    assert second["ReplicaKeyMetadata"]["KeyId"] == key_id

    # Independent read at the destination: the replica is visible and enabled where it was
    # created, not merely echoed back in the mutating call's own response.
    replica_client = ctx.client("kms", region=replica_region)
    replica_state = _poll_until(
        lambda: replica_client.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Enabled",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert replica_state == "Enabled", f"replica key in {replica_region} is {replica_state!r}"
    primary_cfg = kms.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
    assert any(r["Region"] == replica_region for r in primary_cfg["ReplicaKeys"]), (
        f"primary's replica list {primary_cfg['ReplicaKeys']!r} does not include "
        f"{replica_region!r} after a successful replication"
    )


def _pick_other_region(region):
    for candidate in ("us-west-2", "us-east-1", "eu-west-1"):
        if candidate != region:
            return candidate
    return "ap-southeast-1"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _safe_schedule_delete(client, key_id):
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_cleanup_replica(ctx, region, key_id):
    try:
        client = ctx.client("kms", region=region)
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
