"""generate-data-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "generate-data-key"
GROUP = 'data_keys'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKey returns Plaintext and CiphertextBlob of correct length, and the
    CiphertextBlob is a real KMS-wrapped copy of the Plaintext, not just bytes of the right shape."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-generate-data-key"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    resp = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    assert "Plaintext" in resp, f"GenerateDataKey response missing Plaintext: {sorted(resp)}"
    assert "CiphertextBlob" in resp, f"GenerateDataKey response missing CiphertextBlob: {sorted(resp)}"
    assert len(resp["Plaintext"]) == 32, f"expected AES-256 Plaintext of 32 bytes, got {len(resp['Plaintext'])}"
    assert resp["Plaintext"] != resp["CiphertextBlob"], "Plaintext and CiphertextBlob must not be identical bytes"
    assert key_id in resp["KeyId"], f"GenerateDataKey KeyId {resp['KeyId']!r} does not reference {key_id!r}"

    # Independent read at the destination, through a different operation than the one
    # that produced the ciphertext: Decrypt must recover exactly the returned Plaintext.
    dec_resp = kms.decrypt(CiphertextBlob=resp["CiphertextBlob"], KeyId=key_id)
    assert dec_resp["Plaintext"] == resp["Plaintext"], (
        "Decrypt of GenerateDataKey's CiphertextBlob did not recover the original Plaintext"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
