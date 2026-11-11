"""put-encryption-config-none-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-encryption-config-none-roundtrip"
GROUP = 'encryption-config'
SERVICES = ['xray']


def _poll_until(probe, predicate, timeout_s=300, interval_s=10, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _restore_encryption_config(xr, original: dict) -> None:
    """Restores the account-wide encryption config found at start, only if it differs, since a
    put starts a new UPDATING period; waits for it to settle on ACTIVE."""
    current = xr.get_encryption_config()["EncryptionConfig"]
    if (current.get("Type"), current.get("KeyId")) == (original.get("Type"), original.get("KeyId")):
        return
    if original.get("Type") == "KMS" and original.get("KeyId"):
        xr.put_encryption_config(Type="KMS", KeyId=original["KeyId"])
    else:
        xr.put_encryption_config(Type="NONE")
    _poll_until(
        lambda: xr.get_encryption_config()["EncryptionConfig"],
        lambda c: c["Status"] == "ACTIVE",
        timeout_s=600,
        interval_s=10,
        description="restored encryption config settling on ACTIVE",
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:xray-encryption")
def run(ctx) -> None:
    """PutEncryptionConfig(NONE) reports Type=NONE (UPDATING when it is a real change), and the
    config then settles on ACTIVE with Type=NONE and no KeyId.

    Reference: https://docs.aws.amazon.com/xray/latest/api/API_PutEncryptionConfig.html
    """
    xr = ctx.client("xray")
    original = xr.get_encryption_config()["EncryptionConfig"]
    ctx.on_cleanup(lambda: _restore_encryption_config(xr, original))
    was_none = original["Type"] == "NONE"

    resp = xr.put_encryption_config(Type="NONE")
    cfg = resp["EncryptionConfig"]
    assert cfg["Type"] == "NONE", cfg
    # Only a real change goes through UPDATING; a no-op put may report ACTIVE at once.
    if not was_none:
        assert cfg["Status"] == "UPDATING", (
            f"expected a genuine KMS->NONE change to report UPDATING, got {cfg}"
        )

    final = _poll_until(
        lambda: xr.get_encryption_config()["EncryptionConfig"],
        lambda c: c["Status"] == "ACTIVE",
        timeout_s=600,
        interval_s=10,
        description="encryption config settling on ACTIVE",
    )
    assert final["Type"] == "NONE", final
    assert "KeyId" not in final, f"NONE config must not still report a KeyId: {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
