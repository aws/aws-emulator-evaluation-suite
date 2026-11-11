"""asymmetric-rsa-encrypt-decrypt."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "asymmetric-rsa-encrypt-decrypt"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RSA ENCRYPT_DECRYPT keys round-trip under an explicit EncryptionAlgorithm which is echoed back."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("kms-rsaenc-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="RSA_2048",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    plaintext = b"asymmetric-payload-1234567890"
    # RSA_2048 ciphertexts under RSAES_OAEP are always exactly the modulus size (256 bytes),
    # independent of plaintext length: a stub that fakes the round trip by echoing the
    # plaintext back through encrypt/decrypt (with no real RSA math) cannot produce this
    # fixed-length blob, so this is the assertion that actually exercises the crypto.
    rsa_2048_ciphertext_len = 256

    enc = kms.encrypt(
        KeyId=key_id, Plaintext=plaintext, EncryptionAlgorithm="RSAES_OAEP_SHA_256"
    )
    assert enc["EncryptionAlgorithm"] == "RSAES_OAEP_SHA_256", enc["EncryptionAlgorithm"]
    assert enc["KeyId"] == meta["Arn"], enc["KeyId"]
    assert len(enc["CiphertextBlob"]) == rsa_2048_ciphertext_len, (
        f"an RSA_2048 RSAES_OAEP_SHA_256 ciphertext must be exactly "
        f"{rsa_2048_ciphertext_len} bytes (the modulus size), got {len(enc['CiphertextBlob'])}"
    )

    dec = kms.decrypt(
        CiphertextBlob=enc["CiphertextBlob"],
        KeyId=key_id,
        EncryptionAlgorithm="RSAES_OAEP_SHA_256",
    )
    assert dec["Plaintext"] == plaintext, (f"expected {plaintext!r}, got {dec['Plaintext']!r}")
    assert dec["EncryptionAlgorithm"] == "RSAES_OAEP_SHA_256", dec["EncryptionAlgorithm"]
    assert dec["KeyId"] == meta["Arn"], dec["KeyId"]

    # RSA-OAEP is randomised: encrypting the same plaintext twice yields different blobs
    enc2 = kms.encrypt(
        KeyId=key_id, Plaintext=plaintext, EncryptionAlgorithm="RSAES_OAEP_SHA_256"
    )
    assert len(enc2["CiphertextBlob"]) == rsa_2048_ciphertext_len, (
        f"an RSA_2048 RSAES_OAEP_SHA_256 ciphertext must be exactly "
        f"{rsa_2048_ciphertext_len} bytes (the modulus size), got {len(enc2['CiphertextBlob'])}"
    )
    assert enc2["CiphertextBlob"] != enc["CiphertextBlob"], "RSAES_OAEP must be non-deterministic"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
