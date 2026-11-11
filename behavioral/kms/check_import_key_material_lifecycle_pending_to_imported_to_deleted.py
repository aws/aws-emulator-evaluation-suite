"""import-key-material-lifecycle-pending-to-imported-to-deleted."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-key-material-lifecycle-pending-to-imported-to-deleted"
GROUP = "state-machine"
SERVICES = ["kms"]

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EXTERNAL-origin key starts PendingImport (Encrypt fails), is Enabled and round-trips data
    after ImportKeyMaterial, and returns to PendingImport (Encrypt fails) after
    DeleteImportedKeyMaterial."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    created = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-key-material-lifecycle"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    key_arn = created["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, key_id))

    initial_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert initial_state == "PendingImport", f"expected PendingImport right after create_key, got {initial_state!r}"

    code_before, message_before = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"probe"))
    assert code_before == "KMSInvalidStateException", (
        f"expected KMSInvalidStateException encrypting a PendingImport key, got {code_before!r}"
    )
    assert message_before == f"{key_arn} is pending import.", message_before

    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    public_key = serialization.load_der_public_key(params["PublicKey"])
    key_material = os.urandom(32)  # AES-256: required length for SYMMETRIC_DEFAULT
    encrypted_material = public_key.encrypt(
        key_material,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=encrypted_material,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    enabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        interval_s=2,
    )
    assert enabled["KeyState"] == "Enabled", f"expected Enabled after ImportKeyMaterial, got {enabled['KeyState']!r}"

    plaintext = b"sim2real-kms-imported-material-roundtrip"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"round-trip through the imported material failed: got {decrypted!r}"

    kms.delete_imported_key_material(KeyId=key_id)

    pending_again = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "PendingImport",
        timeout_s=60,
        interval_s=2,
    )
    assert pending_again["KeyState"] == "PendingImport", (
        f"expected PendingImport after DeleteImportedKeyMaterial, got {pending_again['KeyState']!r}"
    )

    code_after, message_after = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=plaintext))
    assert code_after == "KMSInvalidStateException", (
        f"expected KMSInvalidStateException encrypting after DeleteImportedKeyMaterial, got {code_after!r}"
    )
    assert message_after == f"{key_arn} is pending import.", message_after


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
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
