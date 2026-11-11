"""import-key-material-binary-blob-integrity."""
from __future__ import annotations

import os

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "import-key-material-binary-blob-integrity"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """ImportKeyMaterial with a one-bit-corrupted wrapped blob fails with InvalidCiphertextException
    and leaves the key PendingImport; the uncorrupted material imports and yields a working key.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-import-"),
        Origin="EXTERNAL",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-blob-integrity"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    key_material = os.urandom(32)  # AES-256 key material for SYMMETRIC_DEFAULT

    # An Encrypt/Decrypt round-trip alone cannot prove the exact bytes were unwrapped, so
    # flip one bit of the wrapped blob and expect rejection.
    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    public_key = serialization.load_der_public_key(params["PublicKey"])
    wrapped = public_key.encrypt(key_material, oaep)
    corrupted = bytearray(wrapped)
    corrupted[len(corrupted) // 2] ^= 0x01

    code, message = _error(
        lambda: kms.import_key_material(
            KeyId=key_id,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=bytes(corrupted),
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )
    )
    assert code == "InvalidCiphertextException", f"unexpected error code for a corrupted blob: {code!r}"
    # AWS sends InvalidCiphertextException for a corrupted wrapped blob with an empty message.
    assert message == "", f"unexpected message for a corrupted blob: {message!r}"

    state_after_corruption = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after_corruption == "PendingImport", (
        f"a rejected, corrupted import must not install any key material, got "
        f"KeyState={state_after_corruption!r}"
    )

    # The same material, wrapped under a fresh token, is accepted.
    params2 = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    public_key2 = serialization.load_der_public_key(params2["PublicKey"])
    wrapped2 = public_key2.encrypt(key_material, oaep)
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params2["ImportToken"],
        EncryptedKeyMaterial=wrapped2,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    ctx.on_cleanup(lambda: kms.delete_imported_key_material(KeyId=key_id))

    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyState"] == "Enabled", meta["KeyState"]

    plaintext = b"import-key-material-integrity-probe"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"{decrypted!r} != {plaintext!r}"


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the corrupted import to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
