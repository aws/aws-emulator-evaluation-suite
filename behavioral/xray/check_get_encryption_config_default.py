"""get-encryption-config-default."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-encryption-config-default"
GROUP = 'encryption-config'
SERVICES = ['xray']


def _poll_until(probe, predicate, timeout_s=600, interval_s=10, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _settled(xr) -> dict:
    return _poll_until(
        lambda: xr.get_encryption_config()["EncryptionConfig"],
        lambda c: c["Status"] == "ACTIVE",
        timeout_s=600,
        interval_s=10,
        description="encryption config settling on ACTIVE",
    )


def _restore_encryption_config(xr, original: dict) -> None:
    """Cleanup: put back the account-wide config this check found and wait for it to settle."""
    if original.get("Type") == "KMS" and original.get("KeyId"):
        xr.put_encryption_config(Type="KMS", KeyId=original["KeyId"])
    else:
        xr.put_encryption_config(Type="NONE")
    _settled(xr)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:xray-encryption")
def run(ctx) -> None:
    """The default encryption config (Type NONE) reads back from GetEncryptionConfig as Type
    NONE with no KeyId once its Status settles on ACTIVE."""
    xr = ctx.client("xray")
    original = _settled(xr)
    if original["Type"] != "NONE":
        ctx.on_cleanup(lambda: _restore_encryption_config(xr, original))
        xr.put_encryption_config(Type="NONE")
    cfg = _settled(xr)
    assert cfg["Type"] == "NONE", cfg
    assert "KeyId" not in cfg, f"default config must not reference a KMS key: {cfg}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
