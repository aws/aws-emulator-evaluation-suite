"""encrypt-decrypt-no-keyid."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encrypt-decrypt-no-keyid"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Decrypt without specifying KeyId succeeds for symmetric keys (key embedded in ciphertext)."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    plaintext = b"test-no-keyid-on-decrypt"
    enc_resp = kms.encrypt(KeyId=key_id, Plaintext=plaintext)
    ciphertext = enc_resp["CiphertextBlob"]

    # Decrypt without KeyId - symmetric ciphertext encodes the key reference
    dec_resp = kms.decrypt(CiphertextBlob=ciphertext)
    assert dec_resp["Plaintext"] == plaintext, (
        f"decrypt without KeyId returned {dec_resp['Plaintext']!r}, expected {plaintext!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
