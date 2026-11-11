"""e2e-import-external-key-material-then-delete-blocks-decrypt."""
from __future__ import annotations

import os
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-import-external-key-material-then-delete-blocks-decrypt"
GROUP = "e2e"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An imported-material EXTERNAL key round-trips Encrypt/Decrypt; DeleteImportedKeyMaterial
    returns it to PendingImport and Decrypt fails KMSInvalidStateException; re-importing the
    same material decrypts the original ciphertext again."""
    wrap = _oaep_wrapper()

    kms = ctx.client("kms")
    created = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-behav-importdel-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-then-delete-blocks-decrypt"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))
    assert created["KeyMetadata"]["KeyState"] == "PendingImport", (
        f"a freshly created EXTERNAL-origin key must start PendingImport, got "
        f"{created['KeyMetadata']['KeyState']!r}"
    )

    key_material = os.urandom(32)  # AES-256 material for a SYMMETRIC_DEFAULT key
    _do_import(kms, key_id, wrap, key_material)

    enabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Enabled",
        timeout_s=30.0,
        interval_s=1.0,
        what=f"{key_id} to reach Enabled after ImportKeyMaterial",
    )
    assert enabled, "key never reached Enabled after ImportKeyMaterial"

    plaintext = b"sim2real-imported-material-round-trip"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id)["Plaintext"]
    assert decrypted == plaintext, (
        f"positive control: decrypting the just-minted ciphertext must return the original "
        f"plaintext, got {decrypted!r}"
    )

    kms.delete_imported_key_material(KeyId=key_id)

    pending_import = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "PendingImport",
        timeout_s=30.0,
        interval_s=1.0,
        what=f"{key_id} to revert to PendingImport after DeleteImportedKeyMaterial",
    )
    assert pending_import, "key never reverted to PendingImport after DeleteImportedKeyMaterial"

    code, message = _poll_until_refused(
        lambda: kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id),
        timeout_s=30.0,
        interval_s=1.0,
        what=f"Decrypt on {key_id} to start refusing after DeleteImportedKeyMaterial",
    )
    assert code == "KMSInvalidStateException", f"unexpected code: {code!r}"
    assert message == f"{created['KeyMetadata']['Arn']} is pending import.", f"unexpected message: {message!r}"

    _do_import(kms, key_id, wrap, key_material)
    restored = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Enabled",
        timeout_s=30.0,
        interval_s=1.0,
        what=f"{key_id} to reach Enabled after re-ImportKeyMaterial",
    )
    assert restored, "key never reached Enabled after re-ImportKeyMaterial"
    restored_plain = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id)["Plaintext"]
    assert restored_plain == plaintext, (
        f"re-importing the IDENTICAL key material must reopen the SAME ciphertext minted before "
        f"the delete, got {restored_plain!r}"
    )


def _do_import(kms: Any, key_id: str, wrap: Callable[[bytes, bytes], bytes], key_material: bytes) -> None:
    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    wrapped = wrap(params["PublicKey"], key_material)
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )


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


def _poll_until_refused(
    call: Callable[[], Any], *, timeout_s: float, interval_s: float = 1.0, what: str = ""
) -> tuple[str, str]:
    """Repeat call() until it raises ClientError and return (Code, Message); a call that keeps
    succeeding past timeout_s raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            call()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}: the call kept succeeding")


def _poll_until(probe: Callable[[], Any], *, timeout_s: float, interval_s: float = 1.0, what: str = "") -> Any:
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what or 'condition'}; last saw {result!r}")


def _safe_schedule_delete(client: Any, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
