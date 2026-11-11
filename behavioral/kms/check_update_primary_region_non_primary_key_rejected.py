"""update-primary-region-non-primary-key-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-primary-region-non-primary-key-rejected"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion naming a Region without a replica of the key is ValidationException "<key>
    does not have a replica key in the specified Region." and leaves the roles unchanged; after
    replicating into that Region the same call succeeds."""
    region_a = ctx.region
    region_b = _alt_region(region_a)
    region_c = _third_region(region_a, region_b)
    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)
    kms_c = ctx.client("kms", region=region_c)

    primary = kms_a.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-uprn-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )
    key_id = primary["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_a, key_id))
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_b, key_id))
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_c, key_id))

    kms_a.replicate_key(KeyId=key_id, ReplicaRegion=region_b)

    def _replica_enabled() -> dict[str, Any] | None:
        d = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    assert _poll_until(_replica_enabled, timeout_s=300.0, interval_s=5.0) is not None, (
        "replica in region_b never reached Enabled after ReplicateKey"
    )

    # Negative: name a Region (region_c) that has NO replica of this key as the new primary.
    err = _error(
        lambda: kms_a.update_primary_region(KeyId=key_id, PrimaryRegion=region_c)
    )
    assert err["Code"] == "ValidationException", err
    assert err["Message"] == f"{key_id} does not have a replica key in the specified Region.", err

    # Effect absent: roles must be completely unchanged by the rejected call.
    desc_a = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
    desc_b = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
    assert desc_a["MultiRegionKeyType"] == "PRIMARY", desc_a
    assert desc_b["MultiRegionKeyType"] == "REPLICA", desc_b

    # Positive control, same file: give region_c a replica, then retry the IDENTICAL rejected
    # call (KeyId=key_id, PrimaryRegion=region_c) -- proving that the missing replica in the
    # named Region, and not some other blanket restriction, was the actual blocking condition.
    kms_a.replicate_key(KeyId=key_id, ReplicaRegion=region_c)

    def _replica_c_enabled() -> dict[str, Any] | None:
        d = kms_c.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    assert _poll_until(_replica_c_enabled, timeout_s=300.0, interval_s=5.0) is not None, (
        "replica in region_c never reached Enabled after ReplicateKey"
    )

    kms_a.update_primary_region(KeyId=key_id, PrimaryRegion=region_c)

    def _roles_swapped() -> bool:
        a = kms_a.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
        c = kms_c.describe_key(KeyId=key_id)["KeyMetadata"]["MultiRegionConfiguration"]
        return a["MultiRegionKeyType"] == "REPLICA" and c["MultiRegionKeyType"] == "PRIMARY"

    def _probe() -> bool | None:
        return True if _roles_swapped() else None

    assert _poll_until(_probe, timeout_s=180.0, interval_s=5.0) is not None, (
        "positive control: primary/replica roles never swapped after the identical "
        "UpdatePrimaryRegion(PrimaryRegion=region_c) call succeeded once region_c had a replica"
    )


def _alt_region(region: str) -> str:
    return "us-west-2" if region != "us-west-2" else "us-east-1"


def _third_region(region_a: str, region_b: str) -> str:
    for candidate in ("us-east-2", "us-west-1", "us-east-1", "us-west-2"):
        if candidate not in (region_a, region_b):
            return candidate
    return "eu-west-1"


def _safe_schedule_delete(client: Any, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn: Callable[[], Any]) -> dict[str, Any]:
    """The error (Code and Message) of a call real AWS refuses; an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return {"Code": e.get("Code"), "Message": e.get("Message")}
    raise AssertionError(f"expected rejection but the call succeeded: {result!r}")


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
