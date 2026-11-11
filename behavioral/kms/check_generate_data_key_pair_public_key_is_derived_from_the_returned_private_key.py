"""generate-data-key-pair-public-key-is-derived-from-the-returned-private-key."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from behavioral_harness import tags

CHECK = "generate-data-key-pair-public-key-is-derived-from-the-returned-private-key"
GROUP = "data_keys"
SERVICES = ["kms"]

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"
_CONTEXT = {"sim2real": "data-key-pair"}
_OTHER_CONTEXT = {"sim2real": "data-key-pair-other"}


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


def _err_code(fn):
    """Return the botocore Error.Code if fn() raises ClientError; RAISE if fn() SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to be refused but it succeeded")


def _ecdsa_verifies(public_key, signature: bytes, message: bytes) -> bool:
    """True/False for a local ECDSA-SHA256 verification, so the caller can assert with a message."""
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _spki(private_key) -> bytes:
    """DER SubjectPublicKeyInfo of the public half of `private_key`."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKeyPair's PublicKey is the SPKI of PrivateKeyPlaintext and works for RSA-OAEP.
    For WithoutPlaintext, the private key from the wrapped blob derives PublicKey and signs.
    A mismatched pair would lose data encrypted with the published PublicKey.

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPair.html
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-dkpair-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-data-key-pair-derivation"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    # ---------- RSA_2048: the plaintext-bearing form ----------
    pair = kms.generate_data_key_pair(
        KeyId=key_arn, KeyPairSpec="RSA_2048", EncryptionContext=_CONTEXT
    )
    assert pair["KeyPairSpec"] == "RSA_2048", (
        f"expected KeyPairSpec 'RSA_2048', got {pair['KeyPairSpec']!r}"
    )
    assert pair["KeyId"] == key_arn, (
        f"the wrapping CMK must be reported as {key_arn!r}, got {pair['KeyId']!r}"
    )
    private = serialization.load_der_private_key(pair["PrivateKeyPlaintext"], password=None)
    assert isinstance(private, rsa.RSAPrivateKey), type(private).__name__
    assert private.key_size == 2048, (
        f"KeyPairSpec RSA_2048 must yield a 2048-bit private key, got {private.key_size}"
    )

    derived = _spki(private)
    assert pair["PublicKey"] == derived, (
        f"PublicKey must be the SubjectPublicKeyInfo of PrivateKeyPlaintext's public half. "
        f"expected {derived.hex()[:64]}... ({len(derived)}B), actual "
        f"{pair['PublicKey'].hex()[:64]}... ({len(pair['PublicKey'])}B)"
    )
    published = serialization.load_der_public_key(pair["PublicKey"])
    assert isinstance(published, rsa.RSAPublicKey), type(published).__name__
    assert published.public_numbers() == private.public_key().public_numbers(), (
        "the published RSA modulus/exponent must be the returned private key's own — this is the "
        "encoding-independent form of the byte comparison above"
    )

    # --- The pair does real work with AWS out of the loop entirely.
    secret = os.urandom(64)
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    sealed = published.encrypt(secret, oaep)
    assert sealed != secret and len(sealed) == 256, (len(sealed),)
    assert private.decrypt(sealed, oaep) == secret, (
        "a payload sealed with the PublicKey KMS published must open with the PrivateKeyPlaintext "
        "KMS returned — the two halves are not a working key pair"
    )

    # Decrypt independently recovers the wrapped private key byte-for-byte.
    unwrapped = kms.decrypt(
        CiphertextBlob=pair["PrivateKeyCiphertextBlob"], EncryptionContext=_CONTEXT
    )
    assert unwrapped["Plaintext"] == pair["PrivateKeyPlaintext"], (
        "PrivateKeyCiphertextBlob must decrypt to exactly PrivateKeyPlaintext; the recovered "
        f"key is {len(unwrapped['Plaintext'])}B against {len(pair['PrivateKeyPlaintext'])}B"
    )
    assert unwrapped["KeyId"] == key_arn, (
        f"the blob must resolve to the wrapping CMK {key_arn!r}, got {unwrapped['KeyId']!r}"
    )

    # --- The EncryptionContext given to GenerateDataKeyPair really is the blob's AAD.
    code = _err_code(
        lambda: kms.decrypt(
            CiphertextBlob=pair["PrivateKeyCiphertextBlob"], EncryptionContext=_OTHER_CONTEXT
        )
    )
    assert code == ERR_INVALID_CIPHERTEXT, (
        f"the encryption context passed to GenerateDataKeyPair must bind the wrapped private key: "
        f"decrypting under {_OTHER_CONTEXT!r} must raise {ERR_INVALID_CIPHERTEXT}, got {code!r}"
    )
    assert (
        kms.decrypt(
            CiphertextBlob=pair["PrivateKeyCiphertextBlob"], EncryptionContext=_CONTEXT
        )["Plaintext"]
        == pair["PrivateKeyPlaintext"]
    ), "the wrapped private key must survive the refused context attempt intact"

    # ---------- ECC_NIST_P256: the form that returns NO private key ----------
    nop = kms.generate_data_key_pair_without_plaintext(
        KeyId=key_arn, KeyPairSpec="ECC_NIST_P256", EncryptionContext=_CONTEXT
    )
    assert "PrivateKeyPlaintext" not in nop, (
        "GenerateDataKeyPairWithoutPlaintext must not return the private key at all; the response "
        f"carried the keys {sorted(k for k in nop if k != 'ResponseMetadata')!r}"
    )
    assert nop["KeyPairSpec"] == "ECC_NIST_P256", (
        f"expected KeyPairSpec 'ECC_NIST_P256', got {nop['KeyPairSpec']!r}"
    )
    recovered = serialization.load_der_private_key(
        kms.decrypt(
            CiphertextBlob=nop["PrivateKeyCiphertextBlob"], EncryptionContext=_CONTEXT
        )["Plaintext"],
        password=None,
    )
    assert isinstance(recovered, ec.EllipticCurvePrivateKey), type(recovered).__name__
    assert recovered.curve.name == "secp256r1", (
        f"ECC_NIST_P256 must be a secp256r1 key, got {recovered.curve.name!r}"
    )
    recovered_spki = _spki(recovered)
    assert nop["PublicKey"] == recovered_spki, (
        f"the published PublicKey must be derivable from the ONLY copy of the private key, the "
        f"wrapped one. expected {recovered_spki.hex()[:64]}..., actual "
        f"{nop['PublicKey'].hex()[:64]}..."
    )

    # --- And the recovered pair signs and verifies off AWS, with a differential proving the
    # local verifier is checking: a one-bit message change must break it.
    message = b"signed-with-a-recovered-data-key-pair-" + os.urandom(16)
    tampered = message[:-1] + bytes([message[-1] ^ 1])
    signature = recovered.sign(message, ec.ECDSA(hashes.SHA256()))
    ec_published = serialization.load_der_public_key(nop["PublicKey"])
    assert _ecdsa_verifies(ec_published, signature, message) is True, (
        f"a signature made with the recovered private key must verify against the published "
        f"PublicKey — the two halves are not a key pair; signature "
        f"{signature.hex()[:48]}... ({len(signature)}B)"
    )
    assert _ecdsa_verifies(ec_published, signature, tampered) is False, (
        "a one-bit message change must break local ECDSA verification against the published "
        "PublicKey — the local verifier is not checking anything"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
