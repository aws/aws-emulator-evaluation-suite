"""generate-data-key-with-context."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generate-data-key-with-context"
GROUP = 'data_keys'
SERVICES = ['kms']

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"

def _err_code(fn):
    """Call fn(); return its ClientError Error.Code. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a mismatched context real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(
        f"real AWS rejects Decrypt with a mismatched EncryptionContext, but it SUCCEEDED and "
        f"returned {result!r}"
    )

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKey with EncryptionContext: decrypt requires same context."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    context = {"service": "sim2real", "operation": "data-key"}
    resp = kms.generate_data_key(KeyId=key_id, KeySpec="AES_128", EncryptionContext=context)
    ciphertext = resp["CiphertextBlob"]
    plaintext = resp["Plaintext"]
    assert len(plaintext) == 16, f"AES_128 plaintext should be 16 bytes, got {len(plaintext)}"

    # Decrypt with correct context
    dec_resp = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id, EncryptionContext=context)
    assert dec_resp["Plaintext"] == plaintext, (
        "decrypting with the exact original EncryptionContext did not return the original "
        "plaintext data key"
    )

    # Decrypt with wrong context fails
    code = _err_code(
        lambda: kms.decrypt(
            CiphertextBlob=ciphertext,
            KeyId=key_id,
            EncryptionContext={"service": "wrong"},
        )
    )
    assert code == ERR_INVALID_CIPHERTEXT, (
        f"expected {ERR_INVALID_CIPHERTEXT!r} for a mismatched EncryptionContext, got {code!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
