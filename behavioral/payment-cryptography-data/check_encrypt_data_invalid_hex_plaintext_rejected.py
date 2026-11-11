"""encrypt-data-invalid-hex-plaintext-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encrypt-data-invalid-hex-plaintext-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography-data"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """EncryptData rejects PlainText that is not valid hexadecimal with
    ValidationException, while the same key encrypting valid hex (positive control)
    succeeds."""
    key = _create_pc_key(ctx)
    data = ctx.client("payment-cryptography-data")
    attrs = {"Symmetric": {"Mode": "ECB"}}

    data.encrypt_data(
        KeyIdentifier=key["arn"], PlainText="0011223344556677", EncryptionAttributes=attrs
    )

    err = _client_error(
        lambda: data.encrypt_data(
            KeyIdentifier=key["arn"], PlainText="00112233ZZ556677", EncryptionAttributes=attrs
        )
    )
    assert err is not None, "EncryptData with non-hex PlainText 00112233ZZ556677 unexpectedly succeeded"
    code = err.response["Error"]["Code"]
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    msg = err.response["Error"]["Message"]
    expected = (
        "1 validation error detected. Value at '/PlainText' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^(?:[0-9a-fA-F][0-9a-fA-F])+$"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


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
        Tags=[{"Key": "sim2real-owner", "Value": "payment-cryptography-data-suite"}],
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
