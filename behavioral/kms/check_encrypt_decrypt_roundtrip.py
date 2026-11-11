"""encrypt-decrypt-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encrypt-decrypt-roundtrip"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt then Decrypt returns the original plaintext (symmetric key)."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    plaintext = b"sim2real-behavioral-test-plaintext-data"
    enc_resp = kms.encrypt(KeyId=key_id, Plaintext=plaintext)
    ciphertext = enc_resp["CiphertextBlob"]
    assert ciphertext != plaintext, f"encrypt returned plaintext unchanged as ciphertext: {ciphertext!r}"
    assert enc_resp["KeyId"].endswith(key_id) or key_id in enc_resp["KeyId"], (
        f"encrypt response KeyId {enc_resp['KeyId']!r} does not reference the key used {key_id!r}"
    )

    dec_resp = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id)
    assert dec_resp["Plaintext"] == plaintext, (
        f"decrypt returned {dec_resp['Plaintext']!r}, expected original plaintext {plaintext!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
