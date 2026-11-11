"""decrypt-data-ciphertext-wrong-length-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decrypt-data-ciphertext-wrong-length-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography-data"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DecryptData rejects ciphertext whose length is not a multiple of the TDES
    block size for ECB mode with ValidationException, while decrypting the full,
    correctly-sized ciphertext (positive control) succeeds."""
    key = _create_pc_key(ctx)
    data = ctx.client("payment-cryptography-data")
    attrs = {"Symmetric": {"Mode": "ECB"}}
    plaintext = "0011223344556677"

    ciphertext = data.encrypt_data(
        KeyIdentifier=key["arn"], PlainText=plaintext, EncryptionAttributes=attrs
    )["CipherText"]

    dec = data.decrypt_data(
        KeyIdentifier=key["arn"], CipherText=ciphertext, DecryptionAttributes=attrs
    )
    assert dec["PlainText"].upper() == plaintext.upper()

    truncated = ciphertext[:8]  # 4 bytes: not a multiple of the 8-byte TDES block
    assert len(truncated) < len(ciphertext)

    err = _client_error(
        lambda: data.decrypt_data(
            KeyIdentifier=key["arn"], CipherText=truncated, DecryptionAttributes=attrs
        )
    )
    assert err is not None
    assert err.response["Error"]["Code"] == "ValidationException"
    msg = err.response["Error"]["Message"]
    assert msg == "Invalid data provided. Please provide data of length multiple of 16.", (
        f"unexpected ValidationException message {msg!r}"
    )


def _client_error(fn):
    try:
        fn()
    except ClientError as err:
        return err
    return None


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
