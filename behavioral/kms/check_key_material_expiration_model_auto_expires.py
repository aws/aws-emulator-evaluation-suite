"""key-material-expiration-model-auto-expires."""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "key-material-expiration-model-auto-expires"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kms"]


# timing:real-time — ttl: 8 s https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Key material imported with ExpirationModel=KEY_MATERIAL_EXPIRES and a short ValidTo
    becomes unusable for Encrypt once it expires, and DescribeKey reverts KeyState from
    Enabled back to PendingImport; re-importing the same material restores it.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-import-key-material.html
    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")

    created = kms.create_key(
        Origin="EXTERNAL",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-kms-import-expiry-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-key-material-auto-expiry"}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    key_arn = created["Arn"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )

    params = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    public_key = serialization.load_der_public_key(params["PublicKey"])
    key_material = os.urandom(32)  # 256-bit material for SYMMETRIC_DEFAULT (AES-256)
    encrypted_key_material = public_key.encrypt(
        key_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # ValidTo has no minimum, only "must be in the future", so 8 s keeps the wait short.
    valid_to = datetime.now(timezone.utc) + timedelta(seconds=8)
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=encrypted_key_material,
        ExpirationModel="KEY_MATERIAL_EXPIRES",
        ValidTo=valid_to,
    )

    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyState"] == "Enabled", (
        f"expected KeyState Enabled right after ImportKeyMaterial, got {described['KeyState']!r}"
    )

    encrypt_resp = kms.encrypt(KeyId=key_id, Plaintext=b"still-valid")
    assert encrypt_resp["CiphertextBlob"], (
        "expected Encrypt to succeed on freshly imported, unexpired key material"
    )

    def _probe() -> str:
        return kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]

    # Deletion of expired material has no documented promptness, so poll with a generous bound.
    final_state = _poll_until(
        _probe,
        lambda state: state == "PendingImport",
        timeout_s=_budget_s(ctx, 360.0),
        interval_s=1.0,
    )
    if final_state != "PendingImport":
        if _budget_spent(ctx):
            raise TimeoutError("KeyState to revert to PendingImport: the run budget ended first; not graded")
        raise AssertionError(
            f"expected KeyState to revert to PendingImport after ValidTo elapsed, "
            f"still {final_state} after the poll window"
        )

    code, message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"now-expired"))
    assert code == "KMSInvalidStateException", (
        f"expected Encrypt to fail with KMSInvalidStateException once imported key "
        f"material expired, got {code!r}"
    )
    assert message == f"{key_arn} is pending import.", message

    # Expiry is recoverable by re-importing. A symmetric key is bound to the first material
    # it accepted (fresh bytes give IncorrectKeyMaterialException), so the same material is
    # re-wrapped under a new import token.
    restore_params = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    restore_public_key = serialization.load_der_public_key(restore_params["PublicKey"])
    restore_encrypted_material = restore_public_key.encrypt(
        key_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=restore_params["ImportToken"],
        EncryptedKeyMaterial=restore_encrypted_material,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    restored = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert restored["KeyState"] == "Enabled", (
        f"expected KeyState to return to Enabled after re-importing key material into a "
        f"PendingImport key, got {restored['KeyState']!r}"
    )
    restore_encrypt_resp = kms.encrypt(KeyId=key_id, Plaintext=b"restored")
    assert restore_encrypt_resp["CiphertextBlob"], (
        "expected Encrypt to succeed again once fresh key material was imported"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
