"""rsa-encrypt-omitted-algorithm-matches-explicit-default-refusal."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rsa-encrypt-omitted-algorithm-matches-explicit-default-refusal"
GROUP = "errors"
SERVICES = ["kms"]

_INVALID_KEY_USAGE = (
    "InvalidKeyUsageException",
    "Algorithm SYMMETRIC_DEFAULT is incompatible with key spec RSA_2048.",
)


def expect_error(fn, code, message):
    """Call fn(); assert its botocore (Error.Code, Error.Message) equal (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message", ""))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(
        f"expected {(code, message)!r}, but the call succeeded and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt on an RSA_2048 key refuses both the omitted and the explicit SYMMETRIC_DEFAULT
    algorithm with the identical InvalidKeyUsageException; RSAES_OAEP_SHA_256 on the same key
    encrypts and the ciphertext decrypts back, and the key stays Enabled throughout.

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
    """
    kms = ctx.client("kms")
    plaintext = b"sim2real-kms-rsa-default-algorithm"

    rsa_key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="RSA_2048",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=rsa_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    # --- The refusal: EncryptionAlgorithm omitted on the RSA key.
    expect_error(lambda: kms.encrypt(KeyId=rsa_key_id, Plaintext=plaintext), *_INVALID_KEY_USAGE)

    # --- Ties the omission to the explicit default: SYMMETRIC_DEFAULT passed explicitly on the
    # same RSA key is refused with the identical code and message as the omission.
    expect_error(
        lambda: kms.encrypt(
            KeyId=rsa_key_id, Plaintext=plaintext, EncryptionAlgorithm="SYMMETRIC_DEFAULT"
        ),
        *_INVALID_KEY_USAGE,
    )

    # --- Legal neighbour: the compatible algorithm encrypts, echoes it, and a 256-byte RSA_2048
    # ciphertext decrypts back to the original plaintext under the same algorithm.
    encrypted = kms.encrypt(
        KeyId=rsa_key_id, Plaintext=plaintext, EncryptionAlgorithm="RSAES_OAEP_SHA_256"
    )
    assert encrypted["EncryptionAlgorithm"] == "RSAES_OAEP_SHA_256", encrypted["EncryptionAlgorithm"]
    blob = encrypted["CiphertextBlob"]
    assert len(blob) == 256, f"RSA_2048 OAEP ciphertext must be 256 bytes, got {len(blob)}"
    decrypted = kms.decrypt(
        KeyId=rsa_key_id, CiphertextBlob=blob, EncryptionAlgorithm="RSAES_OAEP_SHA_256"
    )
    assert decrypted["Plaintext"] == plaintext, decrypted["Plaintext"]
    assert decrypted["EncryptionAlgorithm"] == "RSAES_OAEP_SHA_256", decrypted["EncryptionAlgorithm"]

    # --- Positive control: a SYMMETRIC_DEFAULT key encrypts with the algorithm omitted and
    # echoes SYMMETRIC_DEFAULT, isolating the refusal to the RSA key's spec.
    sym_key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=sym_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    sym_encrypted = kms.encrypt(KeyId=sym_key_id, Plaintext=plaintext)
    assert sym_encrypted["EncryptionAlgorithm"] == "SYMMETRIC_DEFAULT", (
        sym_encrypted["EncryptionAlgorithm"]
    )

    # --- The key stays Enabled after the refusals, proven by a read.
    after = kms.describe_key(KeyId=rsa_key_id)["KeyMetadata"]
    assert after["KeyState"] == "Enabled", after["KeyState"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
