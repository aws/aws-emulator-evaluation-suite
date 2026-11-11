"""e2e-external-key-import-and-expire."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-external-key-import-and-expire"
GROUP = "e2e"
SERVICES = ["kms"]

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EXTERNAL key is PendingImport and unusable; ImportKeyMaterial makes it Enabled and usable;
    DeleteImportedKeyMaterial returns it to PendingImport with Encrypt failing the same way; and
    re-importing the same material restores it to Enabled and usable.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    created = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Description=ctx.unique_name("sim2real-ext-import-expire-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-external-import-expire"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, key_id))

    assert created["KeyMetadata"]["KeyState"] == "PendingImport", (
        f"a freshly created EXTERNAL-origin key must start PendingImport, got "
        f"{created['KeyMetadata']['KeyState']!r}"
    )

    # positive control's inverse: before any material exists, the key is unusable.
    pending_message = f"{created['KeyMetadata']['Arn']} is pending import."
    code_before, msg_before = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"probe"))
    assert code_before == "KMSInvalidStateException", (
        f"Encrypt on a PendingImport key must raise KMSInvalidStateException, got {code_before!r}"
    )
    assert msg_before == pending_message, f"Encrypt on a PendingImport key: unexpected message {msg_before!r}"

    def _wrap_and_import(material: bytes, import_type: str) -> None:
        params = kms.get_parameters_for_import(
            KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
        )
        public_key = serialization.load_der_public_key(params["PublicKey"])
        encrypted_material = public_key.encrypt(
            material,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        kms.import_key_material(
            KeyId=key_id,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=encrypted_material,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
            ImportType=import_type,
        )

    key_material = os.urandom(32)  # AES-256, required length for SYMMETRIC_DEFAULT
    # The first import raises IncorrectKeyMaterialException unless ImportType is passed explicitly.
    _wrap_and_import(key_material, "NEW_KEY_MATERIAL")

    enabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        interval_s=2,
    )
    assert enabled["KeyState"] == "Enabled", (
        f"key must report Enabled after ImportKeyMaterial, got {enabled['KeyState']!r}"
    )

    plaintext = b"sim2real-kms-external-import-roundtrip"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, (
        f"Encrypt/Decrypt round trip on freshly imported material must return the original "
        f"plaintext, got {decrypted!r}"
    )

    kms.delete_imported_key_material(KeyId=key_id)

    pending_again = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "PendingImport",
        timeout_s=60,
        interval_s=2,
    )
    assert pending_again["KeyState"] == "PendingImport", (
        f"key must revert to PendingImport after DeleteImportedKeyMaterial, got "
        f"{pending_again['KeyState']!r}"
    )

    # depth: genuinely unusable again -- the same Encrypt call that worked above now fails with
    # the same error a freshly-created, never-imported EXTERNAL key would raise.
    code_after, msg_after = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=plaintext))
    assert code_after == "KMSInvalidStateException", (
        f"Encrypt after DeleteImportedKeyMaterial must raise KMSInvalidStateException, got "
        f"{code_after!r}"
    )
    assert msg_after == pending_message, (
        f"Encrypt after DeleteImportedKeyMaterial: unexpected message {msg_after!r}"
    )

    # Re-import the SAME bytes as EXISTING_KEY_MATERIAL: a fresh NEW_KEY_MATERIAL import is accepted
    # but leaves the deleted material slot unfilled, so the key never reaches Enabled.
    _wrap_and_import(key_material, "EXISTING_KEY_MATERIAL")
    restored = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        interval_s=2,
    )
    assert restored["KeyState"] == "Enabled", (
        f"key must report Enabled again after re-importing material, got {restored['KeyState']!r}"
    )
    restore_plaintext = b"sim2real-kms-external-import-restored"
    restore_ciphertext = kms.encrypt(KeyId=key_id, Plaintext=restore_plaintext)["CiphertextBlob"]
    restore_decrypted = kms.decrypt(KeyId=key_id, CiphertextBlob=restore_ciphertext)["Plaintext"]
    assert restore_decrypted == restore_plaintext, (
        f"Encrypt/Decrypt round trip after re-import must return the original plaintext, got "
        f"{restore_decrypted!r}"
    )


def _error(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError.

    An unexpected success raises, so accepting input real AWS refuses is not read as a mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call was expected to fail and it succeeded")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _best_effort_schedule_deletion(kms, key_id):
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
