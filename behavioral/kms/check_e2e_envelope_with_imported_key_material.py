"""e2e-envelope-with-imported-key-material."""
from __future__ import annotations

import os
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-envelope-with-imported-key-material"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key with imported material encrypts and wraps data keys; after DeleteImportedKeyMaterial it is
    PendingImport and Encrypt and Decrypt fail with KMSInvalidStateException and the exact message; importing
    the same bytes under a new wrapping key makes it Enabled and its earlier ciphertexts decrypt again."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    def _wrap(public_key_der, material):
        public_key = serialization.load_der_public_key(public_key_der)
        return public_key.encrypt(
            material,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

    def _import(kms, key_id, material):
        params = kms.get_parameters_for_import(
            KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
        )
        kms.import_key_material(
            KeyId=key_id,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=_wrap(params["PublicKey"], material),
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )
        return params["PublicKey"]

    kms = ctx.client("kms")
    key = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)))

    key_material = os.urandom(32)
    first_wrapping_key = _import(kms, key_id, key_material)
    _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Enabled",
        timeout_s=30,
    )

    plaintext = b"sim2real-imported-material-payload"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"pre-delete baseline: expected {plaintext!r}, got {decrypted!r}"

    data_key = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    assert len(data_key["Plaintext"]) == 32, f"expected a 32-byte AES-256 data key, got {len(data_key['Plaintext'])} bytes"
    data_key_ciphertext = data_key["CiphertextBlob"]
    decrypted_data_key = kms.decrypt(KeyId=key_id, CiphertextBlob=data_key_ciphertext)["Plaintext"]
    assert decrypted_data_key == data_key["Plaintext"], "GenerateDataKey's wrapped copy must decrypt back to the plaintext it returned"

    # --- Break exactly one thing: delete the imported material.
    kms.delete_imported_key_material(KeyId=key_id)
    state_after_delete = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "PendingImport",
        timeout_s=30,
    )
    assert state_after_delete == "PendingImport", (
        f"key must revert to PendingImport after DeleteImportedKeyMaterial, got {state_after_delete!r}"
    )

    pending_message = f"{key['KeyMetadata']['Arn']} is pending import."
    code_enc, msg_enc = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=plaintext))
    assert code_enc == "KMSInvalidStateException", f"Encrypt with material deleted: expected KMSInvalidStateException, got {code_enc!r}"
    assert msg_enc == pending_message, f"Encrypt with material deleted: unexpected message {msg_enc!r}"

    code_dec, msg_dec = _error(lambda: kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext))
    assert code_dec == "KMSInvalidStateException", (
        f"Decrypt of the SAME ciphertext with material deleted: expected KMSInvalidStateException, got {code_dec!r}"
    )
    assert msg_dec == pending_message, f"Decrypt with material deleted: unexpected message {msg_dec!r}"

    code_dec_dk, msg_dec_dk = _error(lambda: kms.decrypt(KeyId=key_id, CiphertextBlob=data_key_ciphertext))
    assert code_dec_dk == "KMSInvalidStateException", (
        f"Decrypt of the data-key ciphertext with material deleted: expected KMSInvalidStateException, got {code_dec_dk!r}"
    )
    assert msg_dec_dk == pending_message, f"Decrypt of the data-key ciphertext: unexpected message {msg_dec_dk!r}"

    # --- Positive control / restore: re-import the IDENTICAL bytes under a freshly minted
    # wrapping key and token (GetParametersForImport never reuses either).
    second_wrapping_key = _import(kms, key_id, key_material)
    assert second_wrapping_key != first_wrapping_key, (
        "each GetParametersForImport must mint a fresh wrapping key pair -- if it did not, the "
        "re-import above proved nothing about the wrapping being real"
    )
    state_after_restore = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Enabled",
        timeout_s=30,
    )
    assert state_after_restore == "Enabled", f"key must reach Enabled after re-ImportKeyMaterial, got {state_after_restore!r}"

    restored = kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
    assert restored == plaintext, (
        f"restore must reopen the ORIGINAL ciphertext (it was orphaned, never invalidated): expected {plaintext!r}, got {restored!r}"
    )
    restored_data_key = kms.decrypt(KeyId=key_id, CiphertextBlob=data_key_ciphertext)["Plaintext"]
    assert restored_data_key == data_key["Plaintext"], (
        "restore must also reopen the data-key ciphertext minted before the delete"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _error(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError.

    An unexpected SUCCESS raises rather than returning a falsy sentinel: a target that
    accepts input real AWS refuses is the strongest signal available and must not read as a
    code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("the call was expected to fail with KMSInvalidStateException and it succeeded")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
