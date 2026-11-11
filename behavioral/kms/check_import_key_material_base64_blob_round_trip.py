"""import-key-material-base64-blob-round-trip."""
from __future__ import annotations

import os

from behavioral_harness import tags

CHECK = "import-key-material-base64-blob-round-trip"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Key material wrapped under GetParametersForImport's RSA-OAEP public key imports into a
    PendingImport EXTERNAL key, which turns Enabled and round-trips Encrypt/Decrypt."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    kms = ctx.client("kms")
    meta_before = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-import-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Origin="EXTERNAL",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-base64-blob-round-trip"}],
    )["KeyMetadata"]
    key_id = meta_before["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    assert meta_before["KeyState"] == "PendingImport", (
        f"an Origin=EXTERNAL key must start PendingImport before material is imported, "
        f"got {meta_before['KeyState']!r}"
    )

    params = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    public_key = load_der_public_key(params["PublicKey"])
    key_material = os.urandom(32)  # AES-256 symmetric key material, per AWS docs
    wrapped = public_key.encrypt(
        key_material,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"expected Enabled after successful import, got {state}"

    plaintext = b"round-trip-check-after-byok-import"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"expected {plaintext!r} after round trip, got {decrypted!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
