"""key-rotation-schedule-server-managed."""
from __future__ import annotations

import datetime as dt
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "key-rotation-schedule-server-managed"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After EnableKeyRotation with no period, GetKeyRotationStatus shows RotationPeriodInDays 365
    and a NextRotationDate about a year out, while ListKeyRotations is still empty."""
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-rotsched-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-rotation-schedule-server-managed"}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))

    before = kms.get_key_rotation_status(KeyId=key_id)
    assert before["KeyRotationEnabled"] is False, before

    kms.enable_key_rotation(KeyId=key_id)

    def _rotation_enabled() -> dict[str, Any] | None:
        status = kms.get_key_rotation_status(KeyId=key_id)
        return status if status["KeyRotationEnabled"] else None

    status = _poll_until(_rotation_enabled, timeout_s=30.0, interval_s=2.0)
    assert status is not None, "KeyRotationEnabled never flipped to True"

    assert status["RotationPeriodInDays"] == 365, status["RotationPeriodInDays"]

    next_rotation = status["NextRotationDate"]
    now = dt.datetime.now(dt.timezone.utc)
    delta_days = (next_rotation - now).total_seconds() / 86400.0
    assert 350.0 <= delta_days <= 380.0, (next_rotation, delta_days)

    # ListKeyRotations lists completed rotations, not the schedule.
    rotations = kms.list_key_rotations(KeyId=key_id)["Rotations"]
    assert rotations == [], rotations


def _safe_schedule_delete(client: Any, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


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
