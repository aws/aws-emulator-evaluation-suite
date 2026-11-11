"""sign-verify-ed25519-raw-and-prehash."""
from __future__ import annotations

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key
import hashlib

from behavioral_harness import tags

CHECK = "sign-verify-ed25519-raw-and-prehash"
GROUP = 'sign_verify'
SERVICES = ['kms']

ERR_VALIDATION = "ValidationException"


def _err(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Ed25519 key signs with ED25519_SHA_512 (RAW) and ED25519_PH_SHA_512 (DIGEST); the RAW
    signature verifies locally, a tampered digest fails Verify, and each rejects the other's type.

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
    """
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="SIGN_VERIFY",
        KeySpec="ECC_NIST_EDWARDS25519",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    pub = kms.get_public_key(KeyId=key_id)
    assert pub["KeySpec"] == "ECC_NIST_EDWARDS25519", pub["KeySpec"]
    assert set(pub["SigningAlgorithms"]) == {"ED25519_SHA_512", "ED25519_PH_SHA_512"}, (
        f"an Ed25519 key must advertise exactly these two signing algorithms, got "
        f"{pub['SigningAlgorithms']!r}"
    )
    public_key = load_der_public_key(pub["PublicKey"])
    assert isinstance(public_key, Ed25519PublicKey), (
        f"the published public key must load as a real Ed25519 point, got {type(public_key).__name__}"
    )

    message = b"message to sign"
    digest = hashlib.sha512(message).digest()

    # ED25519_SHA_512 is pure Ed25519: it hashes MESSAGE itself, so it takes MessageType=RAW.
    raw_sig = kms.sign(
        KeyId=key_id, Message=message, MessageType="RAW", SigningAlgorithm="ED25519_SHA_512"
    )["Signature"]
    assert len(raw_sig) == 64, f"an Ed25519 signature is always 64 bytes, got {len(raw_sig)}"

    # ED25519_PH_SHA_512 is pre-hash Ed25519: the caller supplies the SHA-512 digest, so it takes
    # MessageType=DIGEST. Over the same underlying message this must still differ from raw_sig,
    # because Ed25519-PH and pure Ed25519 sign materially different byte strings.
    prehash_sig = kms.sign(
        KeyId=key_id, Message=digest, MessageType="DIGEST", SigningAlgorithm="ED25519_PH_SHA_512"
    )["Signature"]
    assert len(prehash_sig) == 64, f"an Ed25519 signature is always 64 bytes, got {len(prehash_sig)}"
    assert prehash_sig != raw_sig, (
        "ED25519_SHA_512 (RAW) and ED25519_PH_SHA_512 (DIGEST) must produce different signatures "
        "over the same underlying message — pre-hash Ed25519 is not pure Ed25519"
    )

    # Verify raw_sig locally against the published key; pyca has no Ed25519ph, so prehash_sig
    # is checked through KMS Verify below.
    public_key.verify(raw_sig, message)  # raises InvalidSignature on failure

    v1 = kms.verify(
        KeyId=key_id, Message=message, MessageType="RAW",
        Signature=raw_sig, SigningAlgorithm="ED25519_SHA_512",
    )
    assert v1["SignatureValid"] is True, f"KMS disagrees with the local verifier on raw_sig: {v1!r}"

    # The tamper case below proves Verify actually checks the prehash signature.
    v2 = kms.verify(
        KeyId=key_id, Message=digest, MessageType="DIGEST",
        Signature=prehash_sig, SigningAlgorithm="ED25519_PH_SHA_512",
    )
    assert v2["SignatureValid"] is True, f"KMS Verify rejects its own prehash_sig: {v2!r}"
    # A failed KMS Verify never returns SignatureValid=False in a 200 — it raises
    # KMSInvalidSignatureException. A one-bit digest change must trigger exactly that, or
    # Verify is not checking anything.
    tampered_digest = digest[:-1] + bytes([digest[-1] ^ 1])
    tamper = _err(
        lambda: kms.verify(
            KeyId=key_id, Message=tampered_digest, MessageType="DIGEST",
            Signature=prehash_sig, SigningAlgorithm="ED25519_PH_SHA_512",
        )
    )
    expected_tamper = ("KMSInvalidSignatureException", "")
    assert tamper == expected_tamper, (
        f"expected {expected_tamper!r} for a tampered digest, got {tamper!r}"
    )

    # --- Each algorithm takes exactly one MessageType; the model's two fields are cross-checked
    # against each other, not validated in isolation.
    err = _err(
        lambda: kms.sign(
            KeyId=key_id, Message=digest, MessageType="DIGEST", SigningAlgorithm="ED25519_SHA_512"
        )
    )
    expected = (ERR_VALIDATION, "Message type DIGEST is incompatible with algorithm ED25519_SHA_512.")
    assert err == expected, (
        f"ED25519_SHA_512 with MessageType=DIGEST must be refused with {expected!r}, got {err!r}"
    )
    err2 = _err(
        lambda: kms.sign(
            KeyId=key_id, Message=message, MessageType="RAW", SigningAlgorithm="ED25519_PH_SHA_512"
        )
    )
    expected2 = (ERR_VALIDATION, "Message type RAW is incompatible with algorithm ED25519_PH_SHA_512.")
    assert err2 == expected2, (
        f"ED25519_PH_SHA_512 with MessageType=RAW must be refused with {expected2!r}, got {err2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
