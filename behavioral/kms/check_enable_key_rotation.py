"""enable-key-rotation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enable-key-rotation"
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableKeyRotation + GetKeyRotationStatus returns True."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-enable-key-rotation"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    kms.enable_key_rotation(KeyId=key_id)
    # GetKeyRotationStatus is eventually consistent with EnableKeyRotation on
    # real AWS — the flag can read False for a brief window after enabling.
    status = _poll_until(
        lambda: kms.get_key_rotation_status(KeyId=key_id),
        lambda s: s["KeyRotationEnabled"] is True,
        timeout_s=15,
        interval_s=1.0,
        description="EnableKeyRotation propagation",
    )
    assert status["KeyRotationEnabled"] is True, (
        f"expected KeyRotationEnabled=True after EnableKeyRotation, got {status['KeyRotationEnabled']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
