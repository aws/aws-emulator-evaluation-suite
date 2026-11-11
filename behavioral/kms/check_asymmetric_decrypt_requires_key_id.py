"""asymmetric-decrypt-requires-key-id."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "asymmetric-decrypt-requires-key-id"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"
ERR_VALIDATION = "ValidationException"
MSG_KEYID_NULL = "KeyId must not be null"
# AWS returns InvalidCiphertextException with an empty message for both blob refusals.
MSG_BARE = ""
MSG_WRONG_HASH = ""
ALG_SHA256 = "RSAES_OAEP_SHA_256"
ALG_SHA1 = "RSAES_OAEP_SHA_1"


def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window).

    The ARN guard keeps this teardown off AWS-managed keys and aliases.
    """
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An asymmetric ciphertext is not self-describing: Decrypt without KeyId is refused, and
    the correct OAEP hash is part of the contract (an RSA ciphertext carries no KMS envelope).
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-asymkeyid-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="RSA_2048",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-asymmetric-decrypt-requires-key-id"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))
    assert meta["KeySpec"] == "RSA_2048", meta["KeySpec"]
    assert ALG_SHA256 in meta["EncryptionAlgorithms"], meta["EncryptionAlgorithms"]
    assert ALG_SHA1 in meta["EncryptionAlgorithms"], meta["EncryptionAlgorithms"]

    plaintext = b"asymmetric-needs-an-explicit-key"
    enc = kms.encrypt(KeyId=key_arn, Plaintext=plaintext, EncryptionAlgorithm=ALG_SHA256)
    ciphertext = enc["CiphertextBlob"]
    assert enc["EncryptionAlgorithm"] == ALG_SHA256, enc["EncryptionAlgorithm"]
    assert enc["KeyId"] == key_arn, enc["KeyId"]

    # Omitting KeyId gives TWO distinct refusals, decided by whether EncryptionAlgorithm is set:
    #
    #   Decrypt(blob, EncryptionAlgorithm=RSAES_OAEP_SHA_256)  -- no KeyId
    #     -> ValidationException / "KeyId must not be null".  A non-default EncryptionAlgorithm
    #        makes KeyId mandatory, and that parameter-combination rule is enforced BEFORE the
    #        blob is looked at at all.
    #   Decrypt(blob)  -- no KeyId, no EncryptionAlgorithm
    #     -> InvalidCiphertextException.  The request is now well-formed (algorithm defaults to
    #        SYMMETRIC_DEFAULT), so KMS does try to parse the blob as a symmetric envelope, and
    #        the RSA block is not one.
    #
    # The pair proves the ordering: request validation first, blob parsing second.
    no_keyid = _err(
        lambda: kms.decrypt(CiphertextBlob=ciphertext, EncryptionAlgorithm=ALG_SHA256)
    )
    assert no_keyid == (ERR_VALIDATION, MSG_KEYID_NULL), (
        f"Decrypt without KeyId but WITH EncryptionAlgorithm={ALG_SHA256} must raise "
        f"{ERR_VALIDATION} {MSG_KEYID_NULL!r} (the parameter-combination rule is checked before "
        f"the blob), got {no_keyid!r}"
    )

    bare = _err(lambda: kms.decrypt(CiphertextBlob=ciphertext))
    assert bare == (ERR_INVALID_CIPHERTEXT, MSG_BARE), (
        f"Decrypt with neither KeyId nor EncryptionAlgorithm is a well-formed SYMMETRIC_DEFAULT "
        f"request, so an RSA blob must fail as {ERR_INVALID_CIPHERTEXT} {MSG_BARE!r}, got {bare!r}"
    )

    # --- Break exactly one thing: the OAEP hash. Same key, same blob, supported algorithm,
    # but not the one that produced the ciphertext — the padding check must fail.
    wrong_hash = _err(
        lambda: kms.decrypt(
            CiphertextBlob=ciphertext, KeyId=key_arn, EncryptionAlgorithm=ALG_SHA1
        )
    )
    assert wrong_hash == (ERR_INVALID_CIPHERTEXT, MSG_WRONG_HASH), (
        f"Decrypt with {ALG_SHA1} of a {ALG_SHA256} ciphertext must raise "
        f"{ERR_INVALID_CIPHERTEXT} {MSG_WRONG_HASH!r}, got {wrong_hash!r}"
    )

    # --- Effect absent: neither refusal returned plaintext and neither damaged the blob.
    dec = kms.decrypt(
        CiphertextBlob=ciphertext, KeyId=key_arn, EncryptionAlgorithm=ALG_SHA256
    )
    assert dec["Plaintext"] == plaintext, "the ciphertext must survive both refusals"
    assert dec["KeyId"] == key_arn, dec["KeyId"]
    assert dec["EncryptionAlgorithm"] == ALG_SHA256, dec["EncryptionAlgorithm"]

    # --- Control: the key still works under the other supported algorithm end-to-end, so the
    # refusals above were about the ciphertext/algorithm pairing, not about the key or usage.
    enc_sha1 = kms.encrypt(KeyId=key_arn, Plaintext=plaintext, EncryptionAlgorithm=ALG_SHA1)
    dec_sha1 = kms.decrypt(
        CiphertextBlob=enc_sha1["CiphertextBlob"], KeyId=key_arn, EncryptionAlgorithm=ALG_SHA1
    )
    assert dec_sha1["Plaintext"] == plaintext, dec_sha1["Plaintext"]
    assert dec_sha1["EncryptionAlgorithm"] == ALG_SHA1, dec_sha1["EncryptionAlgorithm"]

    # RSA-OAEP is randomised, so the two blobs must differ even for identical plaintext.
    assert enc_sha1["CiphertextBlob"] != ciphertext, "RSAES_OAEP must be non-deterministic"

    after = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert after["KeyState"] == "Enabled", after["KeyState"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
