"""imported-rsa-private-key-signs-identically-to-the-local-key-it-came-from."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from behavioral_harness import tags

CHECK = "imported-rsa-private-key-signs-identically-to-the-local-key-it-came-from"
GROUP = "key_material_import"
SERVICES = ["kms"]

_DETERMINISTIC_ALG = "RSASSA_PKCS1_V1_5_SHA_256"
_RANDOMISED_ALG = "RSASSA_PSS_SHA_256"

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
                return  # already PendingDeletion
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 3.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or RAISES on timeout."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _rsa_aes_wrap(kms_wrapping_public_der: bytes, material: bytes) -> bytes:
    """Build an RSA_AES_KEY_WRAP_SHA_256 EncryptedKeyMaterial blob for `material`.

    RSAES_OAEP_SHA_256(wrapping key, fresh AES-256 key) || AES-KWP (RFC 5649) of the material;
    the docs concatenate the wrapped AES key FIRST.
    """
    aes_key = os.urandom(32)
    wrapped_material = keywrap.aes_key_wrap_with_padding(aes_key, material)
    pub = serialization.load_der_public_key(kms_wrapping_public_der)
    assert isinstance(pub, rsa.RSAPublicKey), type(pub).__name__
    assert pub.key_size == 2048, f"WrappingKeySpec RSA_2048 must be 2048-bit, got {pub.key_size}"
    wrapped_aes_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    assert len(wrapped_aes_key) == 256, (
        f"a 2048-bit RSA-OAEP block must be 256 bytes, got {len(wrapped_aes_key)}"
    )
    return wrapped_aes_key + wrapped_material


def _local_verify(public_key, signature: bytes, message: bytes, *, pss: bool) -> bool:
    """Verify with pyca/cryptography; True or False, raising on a bad key type.

    KMS signs PSS with a digest-length salt, so MAX_LENGTH would fail a valid signature.
    """
    pad = (
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
        if pss
        else padding.PKCS1v15()
    )
    try:
        public_key.verify(signature, message, pad, hashes.SHA256())
    except InvalidSignature:
        return False
    return True


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """KMS signs with the RSA private key it was given: after an RSA_AES_KEY_WRAP_SHA_256 import,
    GetPublicKey matches the local key's SPKI and the PKCS1v15 signature equals the local one.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html
    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_GetParametersForImport.html
    """
    kms = ctx.client("kms")

    # The key material is generated here, so KMS can only have it through the import; it is
    # imported as unencrypted DER PKCS#8.
    local_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pkcs8_der = local_private.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    expected_spki = local_private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert pkcs8_der[:1] == b"\x30", "PKCS#8 DER must start with a SEQUENCE tag"

    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-rsaimport-"),
        KeyUsage="SIGN_VERIFY",
        KeySpec="RSA_2048",
        Origin="EXTERNAL",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-imported-rsa-private-key"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))
    assert meta["Origin"] == "EXTERNAL", (
        f"an import-origin key must report Origin EXTERNAL, got {meta['Origin']!r}"
    )
    assert meta["KeyState"] == "PendingImport", (
        f"a key with no material yet must be PendingImport, got {meta['KeyState']!r}"
    )

    params = kms.get_parameters_for_import(
        KeyId=key_arn,
        WrappingAlgorithm="RSA_AES_KEY_WRAP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    kms.import_key_material(
        KeyId=key_arn,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=_rsa_aes_wrap(params["PublicKey"], pkcs8_der),
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"],
        lambda state: state == "Enabled",
        timeout_s=120,
        what=f"{key_arn} to reach Enabled after importing RSA private key material",
    )

    # KMS derives the public key from the imported private key.
    pub_resp = kms.get_public_key(KeyId=key_arn)
    assert pub_resp["KeySpec"] == "RSA_2048", (
        f"GetPublicKey must advertise KeySpec RSA_2048, got {pub_resp['KeySpec']!r}"
    )
    assert pub_resp["KeyUsage"] == "SIGN_VERIFY", (
        f"GetPublicKey must advertise KeyUsage SIGN_VERIFY, got {pub_resp['KeyUsage']!r}"
    )
    assert pub_resp["PublicKey"] == expected_spki, (
        f"GetPublicKey must return the SubjectPublicKeyInfo derived from the IMPORTED private "
        f"key. expected {expected_spki.hex()[:64]}... ({len(expected_spki)}B), actual "
        f"{pub_resp['PublicKey'].hex()[:64]}... ({len(pub_resp['PublicKey'])}B)"
    )
    published = serialization.load_der_public_key(pub_resp["PublicKey"])
    assert isinstance(published, rsa.RSAPublicKey), type(published).__name__
    assert published.public_numbers() == local_private.public_key().public_numbers(), (
        "the published modulus/exponent must be the imported key's own"
    )

    # RSASSA_PKCS1_V1_5_SHA_256 is deterministic, so KMS's signature equals the local one.
    message = b"signed-by-a-key-kms-was-given-" + os.urandom(24)
    tampered = message[:-1] + bytes([message[-1] ^ 1])
    assert tampered != message and len(tampered) == len(message), (tampered, message)

    signed = kms.sign(
        KeyId=key_arn, Message=message, MessageType="RAW", SigningAlgorithm=_DETERMINISTIC_ALG
    )
    assert signed["SigningAlgorithm"] == _DETERMINISTIC_ALG, signed["SigningAlgorithm"]
    assert signed["KeyId"] == key_arn, (f"expected {key_arn!r}, got {signed['KeyId']!r}")

    local_signature = local_private.sign(message, padding.PKCS1v15(), hashes.SHA256())
    assert signed["Signature"] == local_signature, (
        f"{_DETERMINISTIC_ALG} is deterministic, so KMS's signature must equal the one computed "
        f"locally with the imported key. expected {local_signature.hex()[:48]}... "
        f"({len(local_signature)}B), actual {signed['Signature'].hex()[:48]}... "
        f"({len(signed['Signature'])}B)"
    )

    # The tampered message proves the local verifier actually checks something.
    assert _local_verify(published, signed["Signature"], message, pss=False) is True, (
        "KMS's PKCS1v15 signature must verify against the published public key"
    )
    assert _local_verify(published, signed["Signature"], tampered, pss=False) is False, (
        "a one-bit message change must break local PKCS1v15 verification — the local verifier "
        "is not checking anything"
    )

    # PSS is randomised: two signatures differ yet both verify, which is why byte-equality is
    # asserted only for the deterministic algorithm.
    pss_first = kms.sign(
        KeyId=key_arn, Message=message, MessageType="RAW", SigningAlgorithm=_RANDOMISED_ALG
    )["Signature"]
    pss_second = kms.sign(
        KeyId=key_arn, Message=message, MessageType="RAW", SigningAlgorithm=_RANDOMISED_ALG
    )["Signature"]
    assert pss_first != pss_second, (
        f"{_RANDOMISED_ALG} salts each signature, so two Sign calls over the same message must "
        f"differ; both returned {pss_first.hex()[:32]}..."
    )
    assert len(pss_first) == len(pss_second) == 256, (
        f"a 2048-bit PSS signature must be 256 bytes, got {len(pss_first)}/{len(pss_second)}"
    )
    for label, sig in (("first", pss_first), ("second", pss_second)):
        assert _local_verify(published, sig, message, pss=True) is True, (
            f"the {label} {_RANDOMISED_ALG} signature must verify against the imported key's "
            f"public half"
        )

    # KMS Verify must accept the signature computed locally, which KMS never saw.
    verdict = kms.verify(
        KeyId=key_arn,
        Message=message,
        Signature=local_signature,
        SigningAlgorithm=_DETERMINISTIC_ALG,
    )
    assert verdict["SignatureValid"] is True, (
        f"KMS Verify must accept a signature computed OUTSIDE KMS with the imported private key; "
        f"got {verdict!r}"
    )
    assert verdict["SigningAlgorithm"] == _DETERMINISTIC_ALG, verdict["SigningAlgorithm"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
