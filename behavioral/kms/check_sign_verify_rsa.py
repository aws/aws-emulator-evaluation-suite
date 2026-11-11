"""sign-verify-rsa."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

from behavioral_harness import tags

CHECK = "sign-verify-rsa"
GROUP = 'sign_verify'
SERVICES = ['kms']


def _err(fn):
    """Return the botocore Error (Code and Message) if fn() raises ClientError, else raise."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected a ClientError, the call succeeded: {result!r}")


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An RSA_2048 Sign result verifies via KMS Verify and locally against GetPublicKey's key;
    a one-bit digest tamper fails both, KMS with KMSInvalidSignatureException."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("kms-sign-verify-rsa-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="RSA_2048",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-sign-verify-rsa"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    message = b"sim2real-sign-verify-test-message"
    digest = hashlib.sha256(message).digest()
    tampered_digest = digest[:-1] + bytes([digest[-1] ^ 1])
    assert tampered_digest != digest, (tampered_digest, digest)

    sign_resp = kms.sign(
        KeyId=key_id,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )
    signature = sign_resp["Signature"]
    assert len(signature) > 0, f"expected a non-empty signature, got {signature!r}"

    verify_resp = kms.verify(
        KeyId=key_id,
        Message=digest,
        MessageType="DIGEST",
        Signature=signature,
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )
    assert verify_resp["SignatureValid"] is True, (
        f"KMS Verify rejected its own Sign output: {verify_resp!r}"
    )

    # Verify locally so a Verify that always answers True cannot pass.
    pub = kms.get_public_key(KeyId=key_id)
    loaded = serialization.load_der_public_key(pub["PublicKey"])
    try:
        loaded.verify(
            signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
    except InvalidSignature:
        raise AssertionError(
            f"the RSASSA_PKCS1_V1_5_SHA_256 signature KMS produced does not verify locally "
            f"against the public key KMS published for {key_id!r} — the two halves are not "
            f"a key pair"
        )

    # A tampered digest must fail locally, or the local verification above is vacuous.
    try:
        loaded.verify(
            signature, tampered_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        raise AssertionError(
            "a one-bit digest change must break local verification — the local verifier is "
            "not checking anything"
        )
    except InvalidSignature:
        pass

    err = _err(
        lambda: kms.verify(
            KeyId=key_id,
            Message=tampered_digest,
            MessageType="DIGEST",
            Signature=signature,
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
    )
    assert err["Code"] == "KMSInvalidSignatureException", (
        f"expected KMSInvalidSignatureException for a tampered digest, got {err!r}"
    )
    # KMS sends KMSInvalidSignatureException with no message at all.
    assert err["Message"] == "", f"KMSInvalidSignatureException carries no message, got {err!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
