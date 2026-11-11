"""sign-message-type-raw-and-digest-agree-only-when-the-digest-matches."""
from __future__ import annotations

import hashlib
import os
import time

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

from behavioral_harness import tags

CHECK = "sign-message-type-raw-and-digest-agree-only-when-the-digest-matches"
GROUP = "sign_verify"
SERVICES = ["kms"]

_PKCS1 = "RSASSA_PKCS1_V1_5_SHA_256"
_ECDSA = "ECDSA_SHA_256"
ERR_VALIDATION = "ValidationException"


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7 days is the AWS minimum window)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 3.0, what: str = ""):
    """Poll fn() until predicate(value) is true; return the value or raise on timeout."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _err(fn):
    """Return (Code, Message) if fn() raises ClientError; raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call was expected to be refused but it succeeded")


def _verifies(public_key, signature: bytes, message: bytes, *, pkcs1: bool) -> bool:
    """Return whether a local verification succeeds, so the caller can assert with a message."""
    try:
        if pkcs1:
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _make_key(ctx, kms, key_spec: str, label: str) -> str:
    """Create a SIGN_VERIFY CMK of key_spec and wait for the server-side key pair to be ready."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-behav-kms-msgtype-{label}-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec=key_spec,
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-sign-message-type"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))
    _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"],
        lambda state: state == "Enabled",
        timeout_s=120,
        what=f"{key_arn} ({key_spec}) to reach Enabled — the key pair is generated server-side",
    )
    return key_arn


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PKCS1 v1.5 Sign(RAW, m) equals Sign(DIGEST, sha256(m)) but not Sign(RAW, sha256(m)); each
    verifies locally and via Verify, and wrong-length DIGEST payloads are refused. Randomised ECDSA
    signatures differ per call, so they are only checked to verify, not byte-compared.
    """
    kms = ctx.client("kms")

    message = b"message-type-matters-" + os.urandom(32)
    digest = hashlib.sha256(message).digest()
    assert len(digest) == 32, len(digest)
    tampered = message[:-1] + bytes([message[-1] ^ 1])
    assert tampered != message and len(tampered) == len(message), (tampered, message)

    # ---------- RSA_2048 / PKCS1 v1.5: deterministic, so the two forms must AGREE exactly ------
    rsa_arn = _make_key(ctx, kms, "RSA_2048", "rsa")
    rsa_pub = serialization.load_der_public_key(kms.get_public_key(KeyId=rsa_arn)["PublicKey"])

    sig_raw = kms.sign(
        KeyId=rsa_arn, Message=message, MessageType="RAW", SigningAlgorithm=_PKCS1
    )["Signature"]
    sig_digest = kms.sign(
        KeyId=rsa_arn, Message=digest, MessageType="DIGEST", SigningAlgorithm=_PKCS1
    )["Signature"]
    assert sig_raw == sig_digest, (
        f"{_PKCS1} is deterministic and both forms feed the same SHA-256 into the same padding, "
        f"so Sign(RAW, m) must equal Sign(DIGEST, sha256(m)). RAW gave "
        f"{sig_raw.hex()[:48]}... ({len(sig_raw)}B), DIGEST gave {sig_digest.hex()[:48]}... "
        f"({len(sig_digest)}B)"
    )

    # RAW hashes its input, so signing the DIGEST BYTES as RAW must
    # give a different signature. Without this, a target that ignores MessageType passes above.
    sig_digest_as_raw = kms.sign(
        KeyId=rsa_arn, Message=digest, MessageType="RAW", SigningAlgorithm=_PKCS1
    )["Signature"]
    assert sig_digest_as_raw != sig_digest, (
        "MessageType=RAW must hash its input, so signing the 32 digest bytes as RAW signs "
        "sha256(digest) and cannot equal signing them as DIGEST — this target treats the two "
        "MessageTypes as the same thing"
    )

    # A one-bit change must break local verification, proving the verifier checks something.
    assert _verifies(rsa_pub, sig_raw, message, pkcs1=True) is True, (
        f"the {_PKCS1} signature KMS produced must verify against the public key KMS published; "
        f"signature {sig_raw.hex()[:48]}... ({len(sig_raw)}B)"
    )
    assert _verifies(rsa_pub, sig_raw, tampered, pkcs1=True) is False, (
        "a one-bit message change must break local PKCS1v15 verification of KMS's signature — "
        "the local verifier is not checking anything"
    )

    # Verify must accept the same signature under either MessageType given the matching payload.
    for label, payload, msg_type in (
        ("RAW/message", message, "RAW"),
        ("DIGEST/sha256", digest, "DIGEST"),
    ):
        verdict = kms.verify(
            KeyId=rsa_arn,
            Message=payload,
            MessageType=msg_type,
            Signature=sig_raw,
            SigningAlgorithm=_PKCS1,
        )
        assert verdict["SignatureValid"] is True, (
            f"Verify must accept the signature under {label}; got {verdict!r}"
        )

    # SHA-256 digests are exactly 32 bytes, so 31 and 64 are always invalid.
    for bad_len in (31, 64):
        bad = os.urandom(bad_len)
        code, err_msg = _err(
            lambda _b=bad: kms.sign(
                KeyId=rsa_arn, Message=_b, MessageType="DIGEST", SigningAlgorithm=_PKCS1
            )
        )
        assert code == ERR_VALIDATION, (
            f"MessageType=DIGEST with a {bad_len}-byte payload must be refused with "
            f"{ERR_VALIDATION} — {_PKCS1} needs exactly 32 digest bytes; got {code!r}: "
            f"{err_msg!r}"
        )
        assert "digest" in err_msg.lower(), (
            f"the refusal for a {bad_len}-byte DIGEST payload must name the digest rather than "
            f"reading as a generic validation error: {err_msg!r}"
        )
        expected = f"Digest is invalid length for algorithm {_PKCS1}."
        assert err_msg == expected, (
            f"{bad_len}-byte DIGEST payload: expected message {expected!r}, got {err_msg!r}"
        )

    # The refusals changed nothing about the key.
    assert (
        kms.sign(KeyId=rsa_arn, Message=digest, MessageType="DIGEST", SigningAlgorithm=_PKCS1)[
            "Signature"
        ]
        == sig_digest
    ), "the correct 32-byte DIGEST sign must still return the identical signature after the refusals"

    # ---------- ECC_NIST_P256: randomised, so the two forms must both VERIFY, not match --------
    ec_arn = _make_key(ctx, kms, "ECC_NIST_P256", "ecc")
    ec_pub = serialization.load_der_public_key(kms.get_public_key(KeyId=ec_arn)["PublicKey"])
    ec_raw_a = kms.sign(
        KeyId=ec_arn, Message=message, MessageType="RAW", SigningAlgorithm=_ECDSA
    )["Signature"]
    ec_raw_b = kms.sign(
        KeyId=ec_arn, Message=message, MessageType="RAW", SigningAlgorithm=_ECDSA
    )["Signature"]
    assert ec_raw_a != ec_raw_b, (
        f"ECDSA uses a per-signature nonce, so two {_ECDSA} signatures over the same message must "
        f"differ; both were {ec_raw_a.hex()[:32]}... — a fixed nonce leaks the private key"
    )
    ec_from_digest = kms.sign(
        KeyId=ec_arn, Message=digest, MessageType="DIGEST", SigningAlgorithm=_ECDSA
    )["Signature"]
    for label, sig in (("RAW #1", ec_raw_a), ("RAW #2", ec_raw_b), ("DIGEST", ec_from_digest)):
        assert _verifies(ec_pub, sig, message, pkcs1=False) is True, (
            f"the {label} {_ECDSA} signature must verify locally against the published public "
            f"key; signature {sig.hex()[:48]}... ({len(sig)}B)"
        )
        verdict = kms.verify(
            KeyId=ec_arn, Message=message, Signature=sig, SigningAlgorithm=_ECDSA
        )
        assert verdict["SignatureValid"] is True, (
            f"the {label} ECDSA signature must verify over the original message both locally and "
            f"through KMS Verify; KMS said {verdict!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
