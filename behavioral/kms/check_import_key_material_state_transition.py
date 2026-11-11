"""import-key-material-state-transition."""
from __future__ import annotations

import os
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-key-material-state-transition"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KMS key with Origin=EXTERNAL starts PendingImport, cycles to Enabled after
    ImportKeyMaterial (and is genuinely usable for Encrypt/Decrypt while Enabled), then reverts
    to PendingImport after DeleteImportedKeyMaterial removes the material."""
    wrap = _oaep_wrapper()

    kms = ctx.client("kms")
    created = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-import-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-key-material-state-transition"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    key_arn = created["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))
    assert created["KeyMetadata"]["KeyState"] == "PendingImport", created["KeyMetadata"]["KeyState"]

    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    import_token = params["ImportToken"]
    public_key_der = params["PublicKey"]

    key_material = os.urandom(32)  # AES-256 material for a SYMMETRIC_DEFAULT key
    wrapped = wrap(public_key_der, key_material)

    kms.import_key_material(
        KeyId=key_id,
        ImportToken=import_token,
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    def _left_pending_import() -> dict[str, Any] | None:
        d = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] != "PendingImport" else None

    enabled_desc = _poll_until(_left_pending_import, timeout_s=30.0, interval_s=1.0)
    assert enabled_desc is not None, "key never left PendingImport after ImportKeyMaterial"
    assert enabled_desc["KeyState"] == "Enabled", (
        f"expected Enabled after ImportKeyMaterial, got {enabled_desc['KeyState']!r}"
    )

    # Prove the imported material is genuinely usable, not just a state-label flip.
    plaintext = b"sim2real-imported-material-round-trip"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id)["Plaintext"]
    assert decrypted == plaintext, decrypted

    kms.delete_imported_key_material(KeyId=key_id)

    def _left_enabled() -> dict[str, Any] | None:
        d = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        return d if d["KeyState"] != "Enabled" else None

    reverted = _poll_until(_left_enabled, timeout_s=30.0, interval_s=1.0)
    assert reverted is not None, "key never left Enabled after DeleteImportedKeyMaterial"
    assert reverted["KeyState"] == "PendingImport", (
        f"expected PendingImport after DeleteImportedKeyMaterial, got {reverted['KeyState']!r}"
    )

    # And prove the reversion is a real enforcement point, not just a label: the key must
    # genuinely refuse to encrypt once its material is gone, not merely report a new KeyState.
    code, message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=plaintext))
    assert code == "KMSInvalidStateException", (
        f"expected KMSInvalidStateException encrypting with the imported material deleted, "
        f"got {code!r}"
    )
    assert message == f"{key_arn} is pending import.", message


def _oaep_wrapper() -> Callable[[bytes, bytes], bytes]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    def _wrap(public_key_der: bytes, key_material: bytes) -> bytes:
        public_key = serialization.load_der_public_key(public_key_der)
        return public_key.encrypt(
            key_material,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    return _wrap


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call was expected to fail and it succeeded")


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
