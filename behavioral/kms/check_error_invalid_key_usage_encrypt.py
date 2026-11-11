"""error-invalid-key-usage-encrypt."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-invalid-key-usage-encrypt"
GROUP = 'errors'
SERVICES = ['kms']

ERR_INVALID_KEY_USAGE = "InvalidKeyUsageException"

def _client_error(fn):
    """Return the botocore Error if fn() raises ClientError; raise on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Positive control: encrypt succeeds with an ENCRYPT_DECRYPT key. Encrypt with a SIGN_VERIFY
    key raises InvalidKeyUsageException."""
    kms = ctx.client("kms")

    control_key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=control_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    control_resp = kms.encrypt(KeyId=control_key_id, Plaintext=b"test")
    assert control_resp["CiphertextBlob"], "positive control: encrypt with an ENCRYPT_DECRYPT key must produce ciphertext"

    key_meta = kms.create_key(KeyUsage="SIGN_VERIFY", KeySpec="RSA_2048")["KeyMetadata"]
    key_id = key_meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    err = _client_error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"test"))
    assert err["Code"] == ERR_INVALID_KEY_USAGE, f"Expected {ERR_INVALID_KEY_USAGE}, got {err!r}"
    expected = f"{key_meta['Arn']} key usage is SIGN_VERIFY which is not valid for Encrypt."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
