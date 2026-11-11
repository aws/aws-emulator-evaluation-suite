"""sep-kms-key-scope-signature-from-one-key-fails-verify-under-another-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-signature-from-one-key-fails-verify-under-another-rejected"
GROUP = "key-separation"
SERVICES = ["kms"]

_ALG = "ECDSA_SHA_256"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Key A's ECDSA signature verifies under A (in KMS and locally) but fails under a second
    P-256 key B with KMSInvalidSignatureException and fails locally against B's public key, so
    the separation lives in the key material.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    kms = ctx.client("kms")
    key_a = _new_sign_key(ctx, kms, "a")
    key_b = _new_sign_key(ctx, kms, "b")
    message = b"sep-message-signed-by-key-a"

    pub_a = serialization.load_der_public_key(kms.get_public_key(KeyId=key_a)["PublicKey"])
    pub_b = serialization.load_der_public_key(kms.get_public_key(KeyId=key_b)["PublicKey"])
    raw = serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    assert pub_a.public_bytes(*raw) != pub_b.public_bytes(*raw), (
        "two ECC_NIST_P256 keys must have distinct public keys"
    )

    sig = kms.sign(KeyId=key_a, Message=message, MessageType="RAW", SigningAlgorithm=_ALG)
    assert sig["KeyId"] == key_a, f"Sign must report key A, got {sig['KeyId']!r}"
    signature = sig["Signature"]

    # Positive controls: verifies under A in KMS, and locally against A's public key.
    ok = kms.verify(
        KeyId=key_a, Message=message, MessageType="RAW", Signature=signature, SigningAlgorithm=_ALG
    )
    assert ok["SignatureValid"] is True, f"A's signature must verify under A, got {ok!r}"
    pub_a.verify(signature, message, ec.ECDSA(hashes.SHA256()))

    # KMS sends KMSInvalidSignatureException with no message at all.
    err = _rejected(
        lambda: kms.verify(
            KeyId=key_b, Message=message, MessageType="RAW", Signature=signature,
            SigningAlgorithm=_ALG,
        )
    )
    assert err["Code"] == "KMSInvalidSignatureException", (
        f"key A's signature verified under key B must raise KMSInvalidSignatureException, got "
        f"{err!r}"
    )
    assert err["Message"] == "", f"KMSInvalidSignatureException carries no message, got {err!r}"
    local_b = "valid"
    try:
        pub_b.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        local_b = "invalid"
    assert local_b == "invalid", (
        "key A's signature must NOT verify locally against key B's published public key"
    )

    still = kms.verify(
        KeyId=key_a, Message=message, MessageType="RAW", Signature=signature, SigningAlgorithm=_ALG
    )
    assert still["SignatureValid"] is True, f"A's signature must still verify under A, got {still!r}"


def _new_sign_key(ctx, kms, label):
    """Create an ECC_NIST_P256 signing key and register its scheduled deletion."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-sig-{label}-"),
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _rejected(fn):
    """Return the Code and Message of the expected ClientError; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
