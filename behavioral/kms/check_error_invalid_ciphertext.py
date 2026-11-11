"""error-invalid-ciphertext."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-invalid-ciphertext"
GROUP = 'errors'
SERVICES = ['kms']

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"

def _err_code(fn):
    """Call fn(); return the botocore Error.Code if it raises ClientError. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected a ClientError, call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Decrypt with garbage ciphertext raises InvalidCiphertextException, on a key that
    genuinely decrypts its own ciphertext (positive control)."""
    kms = ctx.client("kms")
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    plaintext = b"positive-control-payload"
    real_ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=real_ciphertext, KeyId=key_id)["Plaintext"]
    assert decrypted == plaintext, f"positive control: expected {plaintext!r}, got {decrypted!r}"

    garbage = b"\x00" * 64
    code = _err_code(lambda: kms.decrypt(CiphertextBlob=garbage, KeyId=key_id))
    assert code == ERR_INVALID_CIPHERTEXT, f"Expected {ERR_INVALID_CIPHERTEXT}, got {code!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
