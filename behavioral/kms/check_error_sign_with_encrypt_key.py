"""error-sign-with-encrypt-key."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-sign-with-encrypt-key"
GROUP = 'errors'
SERVICES = ['kms']

ERR_INVALID_KEY_USAGE = "InvalidKeyUsageException"

def _error(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError; an
    unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Sign with an ENCRYPT_DECRYPT symmetric key raises InvalidKeyUsageException."""
    kms = ctx.client("kms")
    digest = hashlib.sha256(b"test").digest()

    # Positive control: a SIGN_VERIFY key signs the same digest/algorithm successfully,
    # so the negative below cannot be confused with a target that rejects every Sign call.
    sign_key_id = kms.create_key(KeyUsage="SIGN_VERIFY", KeySpec="RSA_2048")["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=sign_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    control_resp = kms.sign(
        KeyId=sign_key_id,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )
    assert len(control_resp["Signature"]) > 0, "positive control: SIGN_VERIFY key failed to sign"

    key_meta = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]
    key_id = key_meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    code, message = _error(
        lambda: kms.sign(
            KeyId=key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
    )
    assert code == ERR_INVALID_KEY_USAGE, f"Expected {ERR_INVALID_KEY_USAGE}, got {code!r}"
    assert message == (
        f"{key_meta['Arn']} key usage is ENCRYPT_DECRYPT which is not valid for Sign."
    ), f"unexpected message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
