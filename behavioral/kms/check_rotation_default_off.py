"""rotation-default-off."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rotation-default-off"
GROUP = 'key_rotation'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Newly created keys have rotation disabled by default."""
    kms = ctx.client("kms")
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    status = kms.get_key_rotation_status(KeyId=key_id)
    assert status["KeyRotationEnabled"] is False, (
        f"expected KeyRotationEnabled=False for a newly created key, got {status['KeyRotationEnabled']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
