"""encryption-context-matching."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encryption-context-matching"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"

def _err_code(fn):
    """Return the botocore Error.Code if fn() raises ClientError. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a mismatched context real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(
        f"real AWS rejects Decrypt with a mismatched EncryptionContext, but it SUCCEEDED "
        f"and returned {result!r}"
    )

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Decrypt fails if EncryptionContext doesn't match what was used during Encrypt."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": ctx.unique_name("behav-kms-encctx-")}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    context = {"purpose": "sim2real-test", "env": "behavioral"}
    plaintext = b"context-sensitive-data"

    enc_resp = kms.encrypt(KeyId=key_id, Plaintext=plaintext, EncryptionContext=context)
    ciphertext = enc_resp["CiphertextBlob"]

    # Correct context succeeds (positive control)
    dec_resp = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id, EncryptionContext=context)
    assert dec_resp["Plaintext"] == plaintext, f"expected {plaintext!r}, got {dec_resp['Plaintext']!r}"

    # Wrong context fails
    code = _err_code(
        lambda: kms.decrypt(
            CiphertextBlob=ciphertext,
            KeyId=key_id,
            EncryptionContext={"purpose": "wrong"},
        )
    )
    assert code == ERR_INVALID_CIPHERTEXT, f"Expected {ERR_INVALID_CIPHERTEXT}, got {code!r}"

    # Restore: the failed attempt authenticated and refused, it did not corrupt the
    # ciphertext — the exact same call that worked before still works identically now.
    dec_resp2 = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id, EncryptionContext=context)
    assert dec_resp2["Plaintext"] == plaintext, (
        f"ciphertext must survive a failed context attempt; expected {plaintext!r}, "
        f"got {dec_resp2['Plaintext']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
