"""mrk-replica-key-rotation-independent-server-managed."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mrk-replica-key-rotation-independent-server-managed"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableKeyRotation on a multi-Region replica fails with UnsupportedOperationException;
    enabling it on the primary syncs the setting and RotationPeriodInDays to the replica."""
    region_a = ctx.region
    # Replication needs a second Region; the choice is arbitrary.
    region_b = _alt_region(region_a)
    kms_a = ctx.client("kms")
    kms_b = ctx.client("kms", region=region_b)

    primary = kms_a.create_key(MultiRegion=True, Description=ctx.unique_name("sim2real-mrkrot-"))
    key_id = primary["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_a, key_id))

    kms_a.replicate_key(KeyId=key_id, ReplicaRegion=region_b)
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms_b, key_id))

    def _replica_enabled() -> dict[str, Any] | None:
        d = kms_b.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] == "Enabled" else None

    replica_ready = _poll_until(_replica_enabled, timeout_s=300.0, interval_s=5.0)
    assert replica_ready is not None, "replica never reached KeyState=Enabled"

    replica_denied_code, replica_denied_msg = _error(
        lambda: kms_b.enable_key_rotation(KeyId=key_id, RotationPeriodInDays=90)
    )
    assert replica_denied_code == "UnsupportedOperationException", replica_denied_code
    replica_arn = replica_ready["Arn"]
    assert replica_denied_msg == (
        f"{replica_arn} is a multi-region replica key which is not valid for EnableKeyRotation."
    ), replica_denied_msg

    primary_before = kms_a.get_key_rotation_status(KeyId=key_id)
    assert primary_before["KeyRotationEnabled"] is False, primary_before
    replica_before = kms_b.get_key_rotation_status(KeyId=key_id)
    assert replica_before["KeyRotationEnabled"] is False, replica_before

    kms_a.enable_key_rotation(KeyId=key_id, RotationPeriodInDays=180)

    def _primary_rotation_on() -> dict[str, Any] | None:
        s = kms_a.get_key_rotation_status(KeyId=key_id)
        return s if s["KeyRotationEnabled"] else None

    primary_status = _poll_until(_primary_rotation_on, timeout_s=30.0, interval_s=2.0)
    assert primary_status is not None, "primary rotation never enabled"
    assert primary_status["RotationPeriodInDays"] == 180, primary_status

    # KMS syncs the shared rotation setting to the replica asynchronously.
    def _replica_rotation_synced() -> dict[str, Any] | None:
        s = kms_b.get_key_rotation_status(KeyId=key_id)
        return s if s["KeyRotationEnabled"] else None

    replica_status = _poll_until(_replica_rotation_synced, timeout_s=120.0, interval_s=5.0)
    assert replica_status is not None, "replica rotation setting was never synchronized"
    assert replica_status["RotationPeriodInDays"] == 180, replica_status


def _alt_region(region: str) -> str:
    return "us-west-2" if region != "us-west-2" else "us-east-1"


def _safe_schedule_delete(client: Any, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
