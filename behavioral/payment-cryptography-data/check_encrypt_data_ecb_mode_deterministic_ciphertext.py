"""encrypt-data-ecb-mode-deterministic-ciphertext."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "encrypt-data-ecb-mode-deterministic-ciphertext"
GROUP = "data-plane"
SERVICES = ["payment-cryptography-data"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """EncryptData in ECB mode returns identical ciphertext for the same plaintext twice and identical
    ciphertext blocks for two identical TDES plaintext blocks (CBC chaining would differ), and
    DecryptData round-trips the plaintext."""
    key = _create_pc_key(ctx)
    data = ctx.client("payment-cryptography-data")
    block = "0102030405060708"
    plaintext = block + block  # two identical 8-byte TDES blocks in one message
    attrs = {"Symmetric": {"Mode": "ECB"}}

    enc1 = data.encrypt_data(
        KeyIdentifier=key["arn"], PlainText=plaintext, EncryptionAttributes=attrs
    )
    enc2 = data.encrypt_data(
        KeyIdentifier=key["arn"], PlainText=plaintext, EncryptionAttributes=attrs
    )
    ct1 = enc1["CipherText"].upper()
    ct2 = enc2["CipherText"].upper()
    assert ct1 == ct2, f"ECB must be deterministic call-to-call: {ct1!r} != {ct2!r}"

    cblock1, cblock2 = ct1[:16], ct1[16:32]
    assert cblock1 == cblock2, (
        f"ECB must encrypt identical plaintext blocks to identical ciphertext "
        f"blocks within one message: {cblock1!r} != {cblock2!r}"
    )

    dec = data.decrypt_data(
        KeyIdentifier=key["arn"],
        CipherText=enc1["CipherText"],
        DecryptionAttributes=attrs,
    )
    got = dec["PlainText"].upper()
    assert got == plaintext.upper(), f"round-trip mismatch: {got!r} != {plaintext.upper()!r}"


def _create_pc_key(ctx):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_2KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
            "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
        },
    )
    key = resp["Key"]
    arn = key["KeyArn"]

    def _cleanup():
        try:
            pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": arn, "kcv": key["KeyCheckValue"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
