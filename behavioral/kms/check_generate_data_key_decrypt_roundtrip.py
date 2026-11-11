"""generate-data-key-decrypt-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "generate-data-key-decrypt-roundtrip"
GROUP = 'data_keys'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKey's CiphertextBlob can be decrypted back to the Plaintext."""
    kms = ctx.client("kms")
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    gen_resp = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    plaintext_key = gen_resp["Plaintext"]
    ciphertext_blob = gen_resp["CiphertextBlob"]
    assert ciphertext_blob != plaintext_key, (
        f"CiphertextBlob must not equal Plaintext (no-op encryption): "
        f"ciphertext={ciphertext_blob!r} plaintext={plaintext_key!r}"
    )

    dec_resp = kms.decrypt(CiphertextBlob=ciphertext_blob, KeyId=key_id)
    assert dec_resp["Plaintext"] == plaintext_key, (
        f"Decrypt(GenerateDataKey's CiphertextBlob) must return the original Plaintext: "
        f"expected={plaintext_key!r} actual={dec_resp['Plaintext']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
