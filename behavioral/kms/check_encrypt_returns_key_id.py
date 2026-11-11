"""encrypt-returns-key-id."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encrypt-returns-key-id"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt response's KeyId is the real ARN of the key used, and that ARN is a working key reference."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    expected_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]

    resp = kms.encrypt(KeyId=key_id, Plaintext=b"test")
    returned_key = resp["KeyId"]
    assert returned_key == expected_arn, f"encrypt response KeyId {returned_key!r} != real key ARN {expected_arn!r}"

    # Terminal independent read: the returned KeyId must be a usable reference to the
    # encrypting key, not merely a string that happens to look like its ARN.
    dec_resp = kms.decrypt(CiphertextBlob=resp["CiphertextBlob"], KeyId=returned_key)
    assert dec_resp["Plaintext"] == b"test", f"decrypt via returned KeyId {returned_key!r} gave {dec_resp['Plaintext']!r}, want b'test'"
    assert dec_resp["KeyId"] == expected_arn, f"decrypt response KeyId {dec_resp['KeyId']!r} != {expected_arn!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
