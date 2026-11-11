"""disabled-key-blocks-update-primary-region-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disabled-key-blocks-update-primary-region-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion on a disabled primary fails DisabledException and leaves the roles
    unchanged, even with an Enabled replica in the target region; after EnableKey the same
    promotion succeeds and swaps the roles."""
    region_a = ctx.region
    region_b = _alt_region(region_a)
    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)

    primary = kms_a.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-disupr-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    key_id = primary["KeyMetadata"]["KeyId"]
    key_arn = primary["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_a, key_id))
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_b, key_id))

    kms_a.replicate_key(KeyId=key_id, ReplicaRegion=region_b)

    def _replica_enabled() -> dict[str, Any] | None:
        d = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    assert _poll_until(_replica_enabled, timeout_s=300.0, interval_s=5.0) is not None, (
        f"replica {key_id!r} in {region_b!r} never reached KeyState=Enabled within 300s"
    )

    kms_a.disable_key(KeyId=key_id)

    def _disabled() -> dict[str, Any] | None:
        d = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Disabled" else None

    assert _poll_until(_disabled, timeout_s=30.0, interval_s=2.0) is not None, (
        f"primary {key_id!r} never reached KeyState=Disabled within 30s of DisableKey"
    )

    err = _error(lambda: kms_a.update_primary_region(KeyId=key_id, PrimaryRegion=region_b))
    assert err.get("Code") == "DisabledException", err
    assert err.get("Message") == f"{key_arn} is disabled.", err

    mrc_a = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
    mrc_b = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
    assert mrc_a["MultiRegionKeyType"] == "PRIMARY", mrc_a
    assert mrc_b["MultiRegionKeyType"] == "REPLICA", mrc_b

    kms_a.enable_key(KeyId=key_id)

    def _enabled() -> dict[str, Any] | None:
        d = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    assert _poll_until(_enabled, timeout_s=30.0, interval_s=2.0) is not None, (
        f"primary {key_id!r} never reached KeyState=Enabled within 30s of the restoring EnableKey"
    )

    kms_a.update_primary_region(KeyId=key_id, PrimaryRegion=region_b)

    def _roles_swapped() -> bool | None:
        a = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
        b = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
        swapped = a["MultiRegionKeyType"] == "REPLICA" and b["MultiRegionKeyType"] == "PRIMARY"
        return True if swapped else None

    assert _poll_until(_roles_swapped, timeout_s=180.0, interval_s=5.0) is not None, (
        "positive control: primary/replica roles never swapped after a correctly-directed "
        "UpdatePrimaryRegion"
    )


def _alt_region(region: str) -> str:
    # Multi-region KMS replication needs a second real AWS region distinct from ctx.region;
    # there is no API to discover "some other available region", so the pair is a literal.
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
