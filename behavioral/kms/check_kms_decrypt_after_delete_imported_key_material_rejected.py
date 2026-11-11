"""kms-decrypt-after-delete-imported-key-material-rejected."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from behavioral_harness import tags

CHECK = "kms-decrypt-after-delete-imported-key-material-rejected"
GROUP = 'key_material_import'
SERVICES = ['kms']

ERR_INVALID_STATE = "KMSInvalidStateException"


def _err(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError.

    An unexpected SUCCESS raises rather than returning a falsy sentinel: a service that accepts
    input real AWS refuses is the strongest signal available and must not read as a name mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call was expected to fail and it succeeded")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted.

    KMS has no prompt delete: the minimum PendingWindowInDays is 7 and a key pending
    deletion still bills, so every key created here carries a 7-day $1/month-prorated
    tail. The ARN guard makes it impossible for this teardown to be pointed at an
    AWS-managed key or resolved through an alias.
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


def _import(kms, key_arn: str, material: bytes) -> bytes:
    """Fetch a FRESH wrapping key + import token, wrap `material` under it, and import.

    Returns the wrapping public key actually used, so the caller can prove the second import used
    a different one. Re-fetching is load-bearing rather than tidy: each GetParametersForImport
    mints a new wrapping key pair and a single-use token, so caching the first wrap would turn
    this check's positive control into a second negative and the check would still "pass".
    """
    params = kms.get_parameters_for_import(
        KeyId=key_arn, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    kms.import_key_material(
        KeyId=key_arn,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=_wrap_for_import(params["PublicKey"], material),
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=120,
        what=f"{key_arn} to activate after ImportKeyMaterial",
    )
    return params["PublicKey"]


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteImportedKeyMaterial the key is PendingImport and Decrypt and Encrypt fail with
    KMSInvalidStateException "<arn> is pending import."; re-importing the same 32 bytes under a new wrapping
    key restores it, and a ciphertext made before the delete decrypts again only with its encryption context."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-delmat-"),
        Origin="EXTERNAL",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-delete-imported-material"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))
    assert meta["KeyState"] == "PendingImport" and meta["Origin"] == "EXTERNAL", meta

    material = os.urandom(32)
    first_wrapping_key = _import(kms, key_arn, material)

    plaintext = b"orphaned-not-invalidated"
    enc_ctx = {"tenant": "acme", "purpose": "delete-material"}
    ct = kms.encrypt(
        KeyId=key_arn, Plaintext=plaintext, EncryptionContext=enc_ctx
    )["CiphertextBlob"]
    assert kms.decrypt(
        CiphertextBlob=ct, KeyId=key_arn, EncryptionContext=enc_ctx
    )["Plaintext"] == plaintext, (
        "pre-state baseline: the ciphertext must open while the material is present"
    )

    # --- Break exactly one thing.
    kms.delete_imported_key_material(KeyId=key_arn)
    meta_gone = _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] == "PendingImport",
        timeout_s=120,
        what=f"{key_arn} to report PendingImport after DeleteImportedKeyMaterial",
    )

    code_dec, message_dec = _err(
        lambda: kms.decrypt(CiphertextBlob=ct, KeyId=key_arn, EncryptionContext=enc_ctx)
    )
    assert code_dec == ERR_INVALID_STATE, (
        f"Decrypt with the imported material deleted must raise {ERR_INVALID_STATE}, got "
        f"{code_dec!r}"
    )
    assert message_dec == f"{key_arn} is pending import.", message_dec
    code_enc, message_enc = _err(lambda: kms.encrypt(KeyId=key_arn, Plaintext=plaintext))
    assert code_enc == ERR_INVALID_STATE, (
        f"Encrypt with the imported material deleted must raise {ERR_INVALID_STATE}, got "
        f"{code_enc!r}"
    )
    assert message_enc == f"{key_arn} is pending import.", message_enc

    # --- Effect absent: the KEY RECORD survives; only the material is gone. Measured, KMS also
    # drops ExpirationModel entirely rather than leaving a stale value behind.
    assert meta_gone["Origin"] == "EXTERNAL", meta_gone["Origin"]
    assert meta_gone["Enabled"] is False, (
        f"the key record itself must survive DeleteImportedKeyMaterial, disabled: {meta_gone!r}"
    )
    assert "ExpirationModel" not in meta_gone, (
        f"with no material there is no expiration model to report, got "
        f"{meta_gone.get('ExpirationModel')!r}"
    )
    assert kms.describe_key(KeyId=key_arn)["KeyMetadata"]["Arn"] == key_arn, (
        "the key ARN must be unchanged"
    )

    # --- Positive control: re-import the IDENTICAL bytes under a NEW wrapping key and token.
    second_wrapping_key = _import(kms, key_arn, material)
    assert second_wrapping_key != first_wrapping_key, (
        "each GetParametersForImport must mint a fresh wrapping key pair — if it did not, the "
        "re-import above proved nothing about the wrapping being real"
    )

    restored = kms.decrypt(CiphertextBlob=ct, KeyId=key_arn, EncryptionContext=enc_ctx)
    assert restored["Plaintext"] == plaintext, (
        "positive control: re-importing the same 32 bytes must reopen the ORIGINAL ciphertext — "
        "the ciphertext was orphaned, never invalidated"
    )
    assert restored["KeyId"] == key_arn, restored["KeyId"]

    # --- And the restore is a restore, not a reset: the AAD binding on the old blob still holds.
    code_ctx, message_ctx = _err(lambda: kms.decrypt(CiphertextBlob=ct, KeyId=key_arn))
    assert code_ctx == "InvalidCiphertextException", (
        f"the reopened ciphertext must still be bound to its encryption context, got "
        f"{code_ctx!r}"
    )
    assert message_ctx == "", f"expected an empty InvalidCiphertextException message, got {message_ctx!r}"

    final = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert final["KeyState"] == "Enabled", final["KeyState"]
    assert final["ExpirationModel"] == "KEY_MATERIAL_DOES_NOT_EXPIRE", final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
