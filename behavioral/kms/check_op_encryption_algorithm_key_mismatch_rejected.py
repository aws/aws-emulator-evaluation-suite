"""op-encryption-algorithm-key-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-encryption-algorithm-key-mismatch-rejected"
GROUP = 'encrypt_decrypt'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SYMMETRIC_DEFAULT must not be accepted on an RSA key, nor RSAES_OAEP on a symmetric key —
    each proven against a positive control on the same key, so the rejection is attributable to
    the algorithm/key mismatch rather than the key being unusable for encryption at all."""
    kms = ctx.client("kms")
    rsa = kms.create_key(
        Description=ctx.unique_name("kms-op-algrsa-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="RSA_2048",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=rsa: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    positive_rsa = kms.encrypt(
        KeyId=rsa, Plaintext=b"data", EncryptionAlgorithm="RSAES_OAEP_SHA_256"
    )
    assert positive_rsa["EncryptionAlgorithm"] == "RSAES_OAEP_SHA_256", (
        f"RSA key + its own algorithm -> got {positive_rsa['EncryptionAlgorithm']}"
    )

    code, message = _error(
        lambda: kms.encrypt(
            KeyId=rsa, Plaintext=b"data", EncryptionAlgorithm="SYMMETRIC_DEFAULT"
        )
    )
    assert code == "InvalidKeyUsageException", f"RSA key + SYMMETRIC_DEFAULT -> got {code}"
    assert message == "Algorithm SYMMETRIC_DEFAULT is incompatible with key spec RSA_2048.", message

    symmetric = kms.create_key(
        Description=ctx.unique_name("kms-op-algsym-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=symmetric: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    positive_sym = kms.encrypt(
        KeyId=symmetric, Plaintext=b"data", EncryptionAlgorithm="SYMMETRIC_DEFAULT"
    )
    assert positive_sym["EncryptionAlgorithm"] == "SYMMETRIC_DEFAULT", (
        f"symmetric key + its own algorithm -> got {positive_sym['EncryptionAlgorithm']}"
    )

    code2, message2 = _error(
        lambda: kms.encrypt(
            KeyId=symmetric, Plaintext=b"data", EncryptionAlgorithm="RSAES_OAEP_SHA_256"
        )
    )
    assert code2 == "InvalidKeyUsageException", f"symmetric key + RSAES_OAEP_SHA_256 -> got {code2}"
    assert message2 == (
        "Algorithm RSAES_OAEP_SHA_256 is incompatible with key spec SYMMETRIC_DEFAULT."
    ), message2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
