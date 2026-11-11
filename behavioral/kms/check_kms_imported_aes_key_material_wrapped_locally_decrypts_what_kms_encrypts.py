"""kms-imported-aes-key-material-wrapped-locally-decrypts-what-kms-encrypts."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from behavioral_harness import tags

CHECK = "kms-imported-aes-key-material-wrapped-locally-decrypts-what-kms-encrypts"
GROUP = 'key_material_import'
SERVICES = ['kms']



def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window).

    The ARN guard keeps this teardown off AWS-managed keys and aliases.
    """
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


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 2.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or raises AssertionError."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _wrap_for_import(public_key_der: bytes, material: bytes) -> bytes:
    """RSAES_OAEP_SHA_256-wrap `material` under the DER wrapping key GetParametersForImport gave."""
    pub = serialization.load_der_public_key(public_key_der)
    return pub.encrypt(
        material,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """32 local AES bytes wrapped with RSAES_OAEP_SHA_256 import into an EXTERNAL key that turns
    Enabled and round-trips Encrypt/Decrypt; its GenerateDataKey output is a working AES-GCM key
    that Decrypt returns byte-identical (it does not prove KMS uses the imported bytes).
    """
    kms = ctx.client("kms")
    meta_before = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-extimport-"),
        Origin="EXTERNAL",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-imported-aes-material"}],
    )["KeyMetadata"]
    key_arn = meta_before["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    assert meta_before["KeyState"] == "PendingImport", (
        f"an Origin=EXTERNAL key must be born PendingImport, got "
        f"{meta_before['KeyState']!r}"
    )
    assert meta_before["Origin"] == "EXTERNAL", meta_before["Origin"]
    assert meta_before["Enabled"] is False, meta_before

    params = kms.get_parameters_for_import(
        KeyId=key_arn, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    assert len(params["PublicKey"]) > 0, params.keys()
    assert len(params["ImportToken"]) > 0, params.keys()
    assert params["KeyId"] == key_arn, params["KeyId"]
    wrapping_pub = serialization.load_der_public_key(params["PublicKey"])
    assert wrapping_pub.key_size == 2048, (
        f"WrappingKeySpec RSA_2048 must yield a 2048-bit wrapping key, got "
        f"{wrapping_pub.key_size}"
    )

    # KMS never sees these bytes unwrapped.
    material = os.urandom(32)
    kms.import_key_material(
        KeyId=key_arn,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=_wrap_for_import(params["PublicKey"], material),
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    meta_after = _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=120,
        what=f"{key_arn} to activate after ImportKeyMaterial",
    )
    assert meta_after["Origin"] == "EXTERNAL", meta_after["Origin"]
    assert meta_after["ExpirationModel"] == "KEY_MATERIAL_DOES_NOT_EXPIRE", (
        f"the key must report the expiration model the import asked for, got "
        f"{meta_after.get('ExpirationModel')!r}"
    )
    assert meta_after["Enabled"] is True, meta_after

    plaintext = b"sealed-under-imported-material"
    enc_ctx = {"tenant": "acme", "purpose": "import"}
    ct = kms.encrypt(
        KeyId=key_arn, Plaintext=plaintext, EncryptionContext=enc_ctx
    )["CiphertextBlob"]
    dec = kms.decrypt(CiphertextBlob=ct, KeyId=key_arn, EncryptionContext=enc_ctx)
    assert dec["Plaintext"] == plaintext, "the imported material does not round-trip"
    assert dec["KeyId"] == key_arn, dec["KeyId"]
    assert dec["EncryptionAlgorithm"] == "SYMMETRIC_DEFAULT", dec["EncryptionAlgorithm"]

    # The data key must be a working AES-256 key, and Decrypt must return that same key.
    dk = kms.generate_data_key(KeyId=key_arn, KeySpec="AES_256", EncryptionContext=enc_ctx)
    assert len(dk["Plaintext"]) == 32, (
        f"AES_256 must yield 32 plaintext key bytes, got {len(dk['Plaintext'])}"
    )
    nonce = os.urandom(12)
    payload = b"a-payload-sealed-locally-with-the-handed-out-data-key"
    aad = b"sim2real-aes-gcm-aad"
    sealed = AESGCM(dk["Plaintext"]).encrypt(nonce, payload, aad)
    assert sealed != payload, "AES-GCM must not return its input"

    recovered = kms.decrypt(
        CiphertextBlob=dk["CiphertextBlob"], KeyId=key_arn, EncryptionContext=enc_ctx
    )["Plaintext"]
    assert recovered == dk["Plaintext"], (
        "Decrypt of the wrapped data key must return the identical bytes GenerateDataKey handed "
        "out in plaintext"
    )
    assert AESGCM(recovered).decrypt(nonce, sealed, aad) == payload, (
        "the data key recovered from KMS could not open a payload sealed with the key KMS handed "
        "out — the two are not the same AES key"
    )

    # The AES-GCM binding is real: the same key with the wrong AAD must not open it.
    try:
        AESGCM(recovered).decrypt(nonce, sealed, b"wrong-aad")
        raise AssertionError("AES-GCM opened the payload under the wrong AAD")
    except Exception as exc:  # cryptography raises InvalidTag
        assert type(exc).__name__ == "InvalidTag", (
            f"the local AES-GCM verifier must reject a wrong AAD with InvalidTag, got "
            f"{type(exc).__name__}: {exc!r}"
        )

    final = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert final["KeyState"] == "Enabled" and final["Origin"] == "EXTERNAL", final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
