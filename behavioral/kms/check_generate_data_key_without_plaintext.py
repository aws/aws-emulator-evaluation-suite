"""generate-data-key-without-plaintext."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "generate-data-key-without-plaintext"
GROUP = 'data_keys'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKeyWithoutPlaintext returns CiphertextBlob but no Plaintext."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-generate-data-key-without-plaintext"}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    resp = kms.generate_data_key_without_plaintext(KeyId=key_id, KeySpec="AES_256")
    assert resp.get("CiphertextBlob"), f"expected a non-empty CiphertextBlob, got {resp.get('CiphertextBlob')!r}"
    assert resp["KeyId"] == meta["Arn"], f"expected KeyId to be the key's ARN {meta['Arn']!r}, got {resp['KeyId']!r}"
    assert "Plaintext" not in resp, (
        f"expected no Plaintext in response, got {resp.get('Plaintext')!r}"
    )
    # The encrypted key can be decrypted
    dec_resp = kms.decrypt(CiphertextBlob=resp["CiphertextBlob"], KeyId=key_id)
    assert len(dec_resp["Plaintext"]) == 32, (
        f"expected a 32-byte AES_256 data key, got {len(dec_resp['Plaintext'])} bytes"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
