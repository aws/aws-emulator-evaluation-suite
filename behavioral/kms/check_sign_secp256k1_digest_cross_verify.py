"""sign-secp256k1-digest-cross-verify."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from behavioral_harness import tags

CHECK = "sign-secp256k1-digest-cross-verify"
GROUP = 'sign_verify'
SERVICES = ['kms']


def _local_verify(public_key, signature: bytes, message: bytes) -> bool:
    """Verify an ECDSA signature with pyca/cryptography. True or False, never raises."""
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A secp256k1 ECDSA_SHA_256 signature made with MessageType=DIGEST and one made with RAW
    each verify under the other MessageType, locally and through KMS, since both sign the same hash.
    """
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="SIGN_VERIFY", KeySpec="ECC_SECG_P256K1",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    message = b"message to sign"
    digest = hashlib.sha256(message).digest()

    raw_sig = kms.sign(
        KeyId=key_id, Message=message, MessageType="RAW", SigningAlgorithm="ECDSA_SHA_256"
    )["Signature"]
    digest_sig = kms.sign(
        KeyId=key_id, Message=digest, MessageType="DIGEST", SigningAlgorithm="ECDSA_SHA_256"
    )["Signature"]
    assert raw_sig and digest_sig

    pub = kms.get_public_key(KeyId=key_id)
    public_key = load_der_public_key(pub["PublicKey"])
    assert isinstance(public_key, ec.EllipticCurvePublicKey), type(public_key).__name__

    # RAW and DIGEST sign the same bytes; they differ only in who computes the hash.
    assert _local_verify(public_key, raw_sig, message) is True, (
        "raw_sig, produced via MessageType=RAW, must verify locally against the message"
    )
    assert _local_verify(public_key, digest_sig, message) is True, (
        "digest_sig, produced via MessageType=DIGEST over sha256(message), must ALSO verify "
        "locally against the plain message — it is the same ECDSA signature over the same hash, "
        "only who computed the hash differs"
    )

    # A one-bit message change must break both, proving the local verifier
    # actually checks something rather than returning True unconditionally.
    tampered = message[:-1] + bytes([message[-1] ^ 1])
    assert _local_verify(public_key, raw_sig, tampered) is False
    assert _local_verify(public_key, digest_sig, tampered) is False

    # Present each signature to KMS Verify under the other MessageType.
    cross1 = kms.verify(
        KeyId=key_id, Message=message, MessageType="RAW",
        Signature=digest_sig, SigningAlgorithm="ECDSA_SHA_256",
    )
    assert cross1["SignatureValid"] is True, (
        f"a DIGEST-mode signature must verify under RAW mode over the same message: {cross1!r}"
    )
    cross2 = kms.verify(
        KeyId=key_id, Message=digest, MessageType="DIGEST",
        Signature=raw_sig, SigningAlgorithm="ECDSA_SHA_256",
    )
    assert cross2["SignatureValid"] is True, (
        f"a RAW-mode signature must verify under DIGEST mode over the same digest: {cross2!r}"
    )

    # KMS Verify must also reject a tampered digest, so the
    # agreement above is not an artifact of Verify always returning True. A failed Verify never
    # returns SignatureValid=False in a 200 — it raises KMSInvalidSignatureException.
    tampered_digest = digest[:-1] + bytes([digest[-1] ^ 1])
    try:
        bad = kms.verify(
            KeyId=key_id, Message=tampered_digest, MessageType="DIGEST",
            Signature=raw_sig, SigningAlgorithm="ECDSA_SHA_256",
        )
        raise AssertionError(f"expected KMSInvalidSignatureException, got a response: {bad!r}")
    except ClientError as exc:
        bad = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
        expected_bad = ("KMSInvalidSignatureException", "")
        assert bad == expected_bad, (
            f"KMS Verify must reject raw_sig against a tampered digest with "
            f"{expected_bad!r}, got {bad!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
