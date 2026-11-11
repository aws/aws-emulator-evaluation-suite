"""put-encryption-config-invalid-kms-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-encryption-config-invalid-kms-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:xray-encryption")
def run(ctx) -> None:
    """PutEncryptionConfig with a nonexistent KMS key fails with InvalidRequestException and the
    account's encryption config is left unchanged; restating the current config succeeds."""
    xray = ctx.client("xray")
    sts = ctx.client("sts")

    _wait_for_active(xray)
    original = xray.get_encryption_config()["EncryptionConfig"]

    # The config is account-wide, so the control only restates its existing value.
    if original.get("Type") == "KMS" and original.get("KeyId"):
        control_resp = xray.put_encryption_config(Type="KMS", KeyId=original["KeyId"])
    else:
        control_resp = xray.put_encryption_config(Type="NONE")
    control_cfg = control_resp["EncryptionConfig"]
    assert control_cfg.get("Type") == original.get("Type", "NONE"), (
        f"expected the no-op positive-control PutEncryptionConfig to echo "
        f"Type={original.get('Type')!r}, got {control_cfg.get('Type')!r}"
    )

    # The control put starts an update; AWS refuses any further put until it settles.
    _wait_for_active(xray)

    account_id = sts.get_caller_identity()["Account"]
    bogus_key_arn = f"arn:aws:kms:{ctx.region}:{account_id}:key/00000000-0000-0000-0000-000000000000"

    code, message = _error(lambda: xray.put_encryption_config(Type="KMS", KeyId=bogus_key_arn))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == "Failed to create grant for customer master key. KMSKeyNotFound", (
        f"unexpected message: {message!r}"
    )

    unchanged = xray.get_encryption_config()["EncryptionConfig"]
    assert unchanged.get("Type") == original.get("Type"), (
        f"expected Type to remain {original.get('Type')!r}, got {unchanged.get('Type')!r}"
    )
    assert unchanged.get("KeyId") == original.get("KeyId"), (
        f"expected KeyId to remain {original.get('KeyId')!r}, got {unchanged.get('KeyId')!r}"
    )
    assert unchanged.get("Status") == "ACTIVE", (
        f"expected a settled EncryptionStatus, got {unchanged.get('Status')!r}"
    )


def _wait_for_active(xray, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    """Poll GetEncryptionConfig until its Status is ACTIVE; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = xray.get_encryption_config()["EncryptionConfig"].get("Status")
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"encryption config still {status!r} after {timeout_s}s")
        time.sleep(interval_s)


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
