"""sign-verify-ecc-p384-signs-only-with-ecdsa-sha-384."""
from __future__ import annotations

import hashlib
import os
import time

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from behavioral_harness import tags

CHECK = "sign-verify-ecc-p384-signs-only-with-ecdsa-sha-384"
GROUP = "sign_verify"
SERVICES = ["kms"]

_ALG = "ECDSA_SHA_384"
_SPEC = "ECC_NIST_P384"
# Order of the NIST P-384 group (FIPS 186-4, D.1.2.4): every ECDSA r and s lies in [1, n-1].
_P384_ORDER = int(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    16,
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _local_ok(public_key, signature: bytes, payload: bytes, *, prehashed: bool) -> bool:
    """True/False for a local ECDSA-SHA384 verification, so the caller asserts with a message."""
    algorithm = Prehashed(hashes.SHA384()) if prehashed else hashes.SHA384()
    try:
        public_key.verify(signature, payload, ec.ECDSA(algorithm))
    except InvalidSignature:
        return False
    return True


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An ECC_NIST_P384 key signs only with ECDSA_SHA_384: RAW and DIGEST signatures verify locally and
    through KMS, a tampered message is KMSInvalidSignatureException with an empty message, and
    ECDSA_SHA_256 is InvalidKeyUsageException."""
    kms = ctx.client("kms")

    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-p384-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec=_SPEC,
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-sign-verify-ecc-p384"}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(_teardown(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7),
        "NotFoundException",
    ))

    deadline = time.monotonic() + 120
    state = meta.get("KeyState")
    while state != "Enabled" and time.monotonic() < deadline:
        time.sleep(3)
        state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"the P-384 key never reached Enabled within 120s: {state!r}"

    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeySpec"] == _SPEC, f"KeySpec is {described.get('KeySpec')!r}, not {_SPEC!r}"
    assert described["KeyUsage"] == "SIGN_VERIFY", f"KeyUsage is {described.get('KeyUsage')!r}"
    assert described.get("SigningAlgorithms") == [_ALG], (
        f"a P-384 key offers exactly [{_ALG!r}], got {described.get('SigningAlgorithms')!r}"
    )

    published = kms.get_public_key(KeyId=key_id)
    assert published.get("SigningAlgorithms") == [_ALG], (
        f"GetPublicKey lists {published.get('SigningAlgorithms')!r}, expected [{_ALG!r}]"
    )
    public_key = serialization.load_der_public_key(published["PublicKey"])
    assert isinstance(public_key, ec.EllipticCurvePublicKey), (
        f"the published key is a {type(public_key).__name__}, not an elliptic-curve key"
    )
    assert public_key.curve.name == "secp384r1" and public_key.key_size == 384, (
        f"the published key is on {public_key.curve.name!r} ({public_key.key_size} bits), "
        f"not secp384r1"
    )

    message = b"sim2real-p384-" + os.urandom(32)
    digest = hashlib.sha384(message).digest()
    assert len(digest) == 48, len(digest)
    tampered = message[:-1] + bytes([message[-1] ^ 1])

    # RAW: KMS hashes with SHA-384 and signs with the P-384 private key.
    raw = kms.sign(KeyId=key_id, Message=message, MessageType="RAW", SigningAlgorithm=_ALG)
    assert raw.get("SigningAlgorithm") == _ALG, f"Sign echoed {raw.get('SigningAlgorithm')!r}"
    sig_raw = raw["Signature"]
    r, s = decode_dss_signature(sig_raw)
    assert 0 < r < _P384_ORDER and 0 < s < _P384_ORDER, (
        f"the RAW signature's (r, s) lie outside the P-384 group order: r={r.bit_length()} bits, "
        f"s={s.bit_length()} bits"
    )
    assert _local_ok(public_key, sig_raw, message, prehashed=False) is True, (
        f"the RAW signature ({len(sig_raw)}B) does not verify locally as ECDSA-SHA384 over the "
        f"message against the key KMS published"
    )
    assert _local_ok(public_key, sig_raw, tampered, prehashed=False) is False, (
        "a one-bit message change must break local verification; the local verifier checks nothing"
    )

    # The RAW signature is a signature over sha384(message), so it verifies as DIGEST through KMS.
    as_digest = kms.verify(KeyId=key_id, Message=digest, MessageType="DIGEST",
                           Signature=sig_raw, SigningAlgorithm=_ALG)
    assert as_digest["SignatureValid"] is True, (
        f"the RAW signature must verify through KMS as DIGEST of the SHA-384 hash: {as_digest!r}"
    )

    # DIGEST: KMS signs the 48 bytes as given; locally it verifies as a prehashed SHA-384 value
    # and as an ordinary signature over the original message.
    sig_digest = kms.sign(KeyId=key_id, Message=digest, MessageType="DIGEST",
                          SigningAlgorithm=_ALG)["Signature"]
    assert _local_ok(public_key, sig_digest, digest, prehashed=True) is True, (
        f"the DIGEST signature ({len(sig_digest)}B) does not verify locally over the prehashed "
        f"SHA-384 value"
    )
    assert _local_ok(public_key, sig_digest, message, prehashed=False) is True, (
        "the DIGEST signature does not verify locally as ECDSA-SHA384 over the original message"
    )
    as_raw = kms.verify(KeyId=key_id, Message=message, MessageType="RAW",
                        Signature=sig_digest, SigningAlgorithm=_ALG)
    assert as_raw["SignatureValid"] is True, (
        f"the DIGEST signature must verify through KMS as RAW over the original message: {as_raw!r}"
    )

    code, msg = _err(lambda: kms.verify(KeyId=key_id, Message=tampered, MessageType="RAW",
                                        Signature=sig_raw, SigningAlgorithm=_ALG))
    assert (code, msg) == ("KMSInvalidSignatureException", ""), (
        f"Verify of a tampered message must be refused with KMSInvalidSignatureException and an "
        f"empty message, got {code!r}: {msg!r}"
    )

    # Over-permissiveness: the key spec fixes the algorithm, for Sign and for Verify.
    incompatible = f"Algorithm ECDSA_SHA_256 is incompatible with key spec {_SPEC}."
    code, msg = _err(lambda: kms.sign(KeyId=key_id, Message=message, MessageType="RAW",
                                      SigningAlgorithm="ECDSA_SHA_256"))
    assert (code, msg) == ("InvalidKeyUsageException", incompatible), (
        f"Sign with ECDSA_SHA_256 on a P-384 key must be refused InvalidKeyUsageException "
        f"{incompatible!r}, got {code!r}: {msg!r}"
    )
    code, msg = _err(lambda: kms.verify(KeyId=key_id, Message=message, MessageType="RAW",
                                        Signature=sig_raw, SigningAlgorithm="ECDSA_SHA_256"))
    assert (code, msg) == ("InvalidKeyUsageException", incompatible), (
        f"Verify with ECDSA_SHA_256 on a P-384 key must be refused InvalidKeyUsageException "
        f"{incompatible!r}, got {code!r}: {msg!r}"
    )

    # Positive control after the refusals: the key still signs with its one algorithm.
    again = kms.sign(KeyId=key_id, Message=message, MessageType="RAW",
                     SigningAlgorithm=_ALG)["Signature"]
    assert _local_ok(public_key, again, message, prehashed=False) is True, (
        "after the refused algorithms, a fresh ECDSA_SHA_384 signature no longer verifies locally"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
