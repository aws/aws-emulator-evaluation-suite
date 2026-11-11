"""disabled-key-blocks-replicate-key-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disabled-key-blocks-replicate-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ReplicateKey on a disabled multi-Region primary fails with DisabledException and the exact message and
    creates no replica (NotFoundException in the target Region, no ReplicaKeys); after EnableKey the same call
    creates a replica that reaches Enabled."""
    region_a = ctx.region
    region_b = _alt_region(region_a)
    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)

    primary = kms_a.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-disrepl-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-disabled-key-blocks-replicate-key"}],
    )
    key_id = primary["KeyMetadata"]["KeyId"]
    key_arn = primary["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_a, key_id))
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_b, key_id))
    assert primary["KeyMetadata"]["MultiRegion"] is True, primary["KeyMetadata"]

    kms_a.disable_key(KeyId=key_id)

    def _disabled() -> dict[str, Any] | None:
        d = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Disabled" else None

    disabled_desc = _poll_until(_disabled, timeout_s=30.0, interval_s=2.0)
    assert disabled_desc is not None, "key never reached Disabled"

    err = _error(lambda: kms_a.replicate_key(KeyId=key_id, ReplicaRegion=region_b))
    assert err.get("Code") == "DisabledException", err
    assert err.get("Message") == f"{key_arn} is disabled.", err

    # Effect absent: no replica exists in region_b, and the primary lists no replicas.
    replica_err = _error(lambda: kms_b.describe_key(KeyId=key_id))
    assert replica_err.get("Code") == "NotFoundException", replica_err
    replica_arn = f"arn:aws:kms:{region_b}:{ctx.account}:key/{key_id}"
    assert replica_err.get("Message") == f"Key '{replica_arn}' does not exist", replica_err
    mrc = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
    assert mrc["ReplicaKeys"] == [], mrc["ReplicaKeys"]

    # Positive control, same file: re-enable the primary, then the same replication succeeds.
    kms_a.enable_key(KeyId=key_id)

    def _enabled() -> dict[str, Any] | None:
        d = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    assert (
        _poll_until(_enabled, timeout_s=30.0, interval_s=2.0) is not None
    ), "key never reached Enabled after enable_key"

    kms_a.replicate_key(
        KeyId=key_id,
        ReplicaRegion=region_b,
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-disabled-key-blocks-replicate-key"}],
    )

    def _replica_enabled() -> dict[str, Any] | None:
        d = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    replica_desc = _poll_until(_replica_enabled, timeout_s=300.0, interval_s=5.0)
    assert replica_desc is not None, "positive control: replica never reached Enabled"
    assert (
        replica_desc["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA"
    ), replica_desc["MultiRegionConfiguration"]


def _alt_region(region: str) -> str:
    return "us-west-2" if region != "us-west-2" else "us-east-1"


def _safe_schedule_delete(client: Any, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn: Callable[[], Any]) -> dict[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
