"""encrypt-decrypt-symmetric-cbc-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "encrypt-decrypt-symmetric-cbc-roundtrip"
GROUP = "data-plane"
SERVICES = ["payment-cryptography-data"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TDES symmetric data-encryption key round-trips plaintext through
    EncryptData -> DecryptData using CBC mode with an explicit IV, and the
    KeyArn/KeyCheckValue echoed back match the control-plane key record."""
    key = _create_pc_key(
        ctx,
        key_algorithm="TDES_2KEY",
        key_usage="TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        modes={"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    )
    data = ctx.client("payment-cryptography-data")
    plaintext = "1122334455667788"  # 8 bytes == 1 TDES block
    attrs = {"Symmetric": {"Mode": "CBC", "InitializationVector": "0000000000000000"}}

    enc = data.encrypt_data(
        KeyIdentifier=key["arn"], PlainText=plaintext, EncryptionAttributes=attrs
    )
    assert enc["KeyArn"] == key["arn"], f"expected KeyArn {key['arn']!r}, got {enc['KeyArn']!r}"
    assert enc["CipherText"].upper() != plaintext.upper(), (
        f"CipherText {enc['CipherText']!r} must not equal the plaintext {plaintext!r}"
    )

    dec = data.decrypt_data(
        KeyIdentifier=key["arn"],
        CipherText=enc["CipherText"],
        DecryptionAttributes=attrs,
    )
    assert dec["KeyArn"] == key["arn"], f"expected KeyArn {key['arn']!r}, got {dec['KeyArn']!r}"
    assert dec["KeyCheckValue"] == key["kcv"], (
        f"expected KeyCheckValue {key['kcv']!r}, got {dec['KeyCheckValue']!r}"
    )
    assert dec["PlainText"].upper() == plaintext.upper(), (
        f"expected round-tripped PlainText {plaintext!r}, got {dec['PlainText']!r}"
    )


def _create_pc_key(ctx, key_algorithm, key_usage, modes, exportable=True):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=exportable,
        KeyAttributes={
            "KeyAlgorithm": key_algorithm,
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": key_usage,
            "KeyModesOfUse": modes,
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
