"""rotate-key-on-demand-records-rotation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "rotate-key-on-demand-records-rotation"
GROUP = 'key_rotation'
SERVICES = ['kms']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateKeyOnDemand triggers an immediate rotation recorded in ListKeyRotations as ON_DEMAND."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("kms-rotatedemand-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    before = kms.list_key_rotations(KeyId=key_id)["Rotations"]
    n_before = len(before)

    resp = kms.rotate_key_on_demand(KeyId=key_id)
    assert resp["KeyId"] in (key_id, meta["Arn"]), resp["KeyId"]

    rotations = _poll_until(
        lambda: kms.list_key_rotations(KeyId=key_id)["Rotations"],
        lambda rs: len(rs) > n_before,
        timeout_s=180,
        interval_s=5,
        description="on-demand rotation recorded in ListKeyRotations",
    )
    assert rotations, "on-demand rotation never showed up in ListKeyRotations"
    assert any(r.get("RotationType") == "ON_DEMAND" for r in rotations), rotations

    # on-demand rotation does not turn on automatic rotation
    status = kms.get_key_rotation_status(KeyId=key_id)
    assert status["KeyRotationEnabled"] is False, (
        f"expected KeyRotationEnabled=False after an on-demand rotation "
        f"(automatic rotation must stay off), got {status['KeyRotationEnabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
