"""verify-tampered-signature-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-tampered-signature-fails"
GROUP = 'sign_verify'
SERVICES = ['kms']


def _err(fn):
    """Return the botocore Error (Code and Message) if fn() raises ClientError. An unexpected
    SUCCESS raises, so a target that accepts the call cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected Verify to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Verify rejects a signature that doesn't validate against the message, with KMSInvalidSignatureException."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("kms-verifytamper-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="RSA_2048",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-verify-tampered-signature-fails"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    message = b"original-message"

    signature = kms.sign(
        KeyId=key_id, Message=message, SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256"
    )["Signature"]

    # Positive control: the untampered signature must verify, so the negatives below
    # are known to be testing against a working verify path rather than a target that
    # rejects every call.
    control = kms.verify(
        KeyId=key_id, Message=message, Signature=signature, SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256"
    )
    assert control["SignatureValid"] is True, f"expected the untampered signature to verify, got {control}"

    tampered = bytearray(signature)
    tampered[0] ^= 0xFF
    err = _err(
        lambda: kms.verify(
            KeyId=key_id,
            Message=message,
            Signature=bytes(tampered),
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
    )
    assert err["Code"] == "KMSInvalidSignatureException", f"expected KMSInvalidSignatureException, got {err!r}"
    # KMS sends KMSInvalidSignatureException with no message at all.
    assert err["Message"] == "", f"KMSInvalidSignatureException carries no message, got {err!r}"

    # verifying against a different message with the original signature must also fail
    err2 = _err(
        lambda: kms.verify(
            KeyId=key_id,
            Message=b"a-different-message",
            Signature=signature,
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
    )
    assert err2["Code"] == "KMSInvalidSignatureException", f"expected KMSInvalidSignatureException, got {err2!r}"
    assert err2["Message"] == "", f"KMSInvalidSignatureException carries no message, got {err2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
