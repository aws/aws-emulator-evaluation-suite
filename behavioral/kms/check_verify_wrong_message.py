"""verify-wrong-message."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-wrong-message"
GROUP = 'sign_verify'
SERVICES = ['kms']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Verify with a tampered message is rejected with KMSInvalidSignatureException."""
    kms = ctx.client("kms")
    try:
        key_id = kms.create_key(
            KeyUsage="SIGN_VERIFY",
            KeySpec="RSA_2048",
            Tags=[{"TagKey": "sim2real", "TagValue": "kms-verify-with-wrong-message"}],
        )["KeyMetadata"]["KeyId"]
        ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    except ClientError as exc:
        if exc.response["Error"]["Code"] in (
            "UnsupportedOperationException",
            "ValidationException",
        ):
            raise
        raise

    message = b"original-message"
    digest = hashlib.sha256(message).digest()
    sign_resp = kms.sign(
        KeyId=key_id,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )
    signature = sign_resp["Signature"]

    # Positive control: the signature must validate against the message it was
    # actually produced over, on the same key and wiring used below.
    positive_resp = kms.verify(
        KeyId=key_id,
        Message=digest,
        MessageType="DIGEST",
        Signature=signature,
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )
    assert positive_resp["SignatureValid"] is True, (
        f"expected SignatureValid=True for the correct message, got {positive_resp['SignatureValid']}"
    )

    # Verify with different message: the identical signature must now be rejected.
    # Per the KMS model, a failed verification never returns SignatureValid=False in
    # a 200 — Verify itself fails with KMSInvalidSignatureException.
    wrong_digest = hashlib.sha256(b"tampered-message").digest()
    try:
        verify_resp = kms.verify(
            KeyId=key_id,
            Message=wrong_digest,
            MessageType="DIGEST",
            Signature=signature,
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        raise AssertionError(
            f"expected KMSInvalidSignatureException for a tampered message, got "
            f"a successful verify: {verify_resp}"
        )
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "KMSInvalidSignatureException", f"expected KMSInvalidSignatureException, got {err!r}"
        # KMS sends KMSInvalidSignatureException with no message at all.
        assert err["Message"] == "", f"KMSInvalidSignatureException carries no message, got {err!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
