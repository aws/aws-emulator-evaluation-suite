"""import-key-material-full-lifecycle."""
from __future__ import annotations

import os
import time

from behavioral_harness import tags

CHECK = "import-key-material-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KMS key with Origin=EXTERNAL starts PendingImport, becomes Enabled and
    usable for Encrypt/Decrypt once ImportKeyMaterial supplies wrapped key material,
    and reverts to PendingImport once DeleteImportedKeyMaterial removes it."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")

    created = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-key-material-full-lifecycle"}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    key_arn = created["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyState"] == "PendingImport", described["KeyState"]

    params = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    import_token = params["ImportToken"]
    public_key_der = params["PublicKey"]

    key_material = os.urandom(32)  # 256-bit AES key material for SYMMETRIC_DEFAULT
    public_key = serialization.load_der_public_key(public_key_der)
    wrapped = public_key.encrypt(
        key_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    kms.import_key_material(
        KeyId=key_id,
        ImportToken=import_token,
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    enabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["KeyState"] != "PendingImport",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert enabled["KeyState"] == "Enabled", enabled["KeyState"]

    # Prove the imported material is actually usable, not just a state-flag flip.
    plaintext = b"sim2real-import-key-material-roundtrip"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, decrypted

    kms.delete_imported_key_material(KeyId=key_id)
    # Poll on "left Enabled" (not "reached PendingImport") so the assert below is not just
    # re-checking the predicate that already gated the poll's return.
    reverted = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["KeyState"] != "Enabled",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert reverted["KeyState"] == "PendingImport", reverted["KeyState"]

    # And now cryptographic operations fail again because material is gone.
    code, message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=plaintext))
    assert code == "KMSInvalidStateException", code
    assert message == f"{key_arn} is pending import.", message


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("the call was expected to fail and it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
