"""translate-pin-data-iso-format-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "translate-pin-data-iso-format-roundtrip"
GROUP = "data-plane"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TranslatePinData moves an ISO format 0 PIN block under PEK1 to a different ISO format 3 block
    under PEK2 that still verifies against the original Visa PVV, while a tampered PVV gets
    VerificationFailedException "Pin block verification failed." with Reason INVALID_PIN."""
    pvk = _create_key(ctx, "TR31_V2_VISA_PIN_VERIFICATION_KEY", {"Generate": True, "Verify": True})
    pek1 = _create_key(
        ctx, "TR31_P0_PIN_ENCRYPTION_KEY",
        {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    )
    pek2 = _create_key(
        ctx, "TR31_P0_PIN_ENCRYPTION_KEY",
        {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    )
    data = ctx.client("payment-cryptography-data")

    gen = data.generate_pin_data(
        GenerationKeyIdentifier=pvk["arn"],
        EncryptionKeyIdentifier=pek1["arn"],
        PrimaryAccountNumber=PAN,
        PinBlockFormat="ISO_FORMAT_0",
        GenerationAttributes={"VisaPin": {"PinVerificationKeyIndex": 1}},
    )
    pvv = gen["PinData"]["VerificationValue"]
    block0 = gen["EncryptedPinBlock"]

    translated = data.translate_pin_data(
        IncomingKeyIdentifier=pek1["arn"],
        OutgoingKeyIdentifier=pek2["arn"],
        IncomingTranslationAttributes={"IsoFormat0": {"PrimaryAccountNumber": PAN}},
        OutgoingTranslationAttributes={"IsoFormat3": {"PrimaryAccountNumber": PAN}},
        EncryptedPinBlock=block0,
    )
    assert translated["KeyArn"] == pek2["arn"], f"expected translate to report PEK2 {pek2['arn']}, got {translated['KeyArn']}"
    block1 = translated["PinBlock"]
    assert block1.upper() != block0.upper(), "translated PIN block must differ from the source block after re-encryption"

    ver = data.verify_pin_data(
        VerificationKeyIdentifier=pvk["arn"],
        EncryptionKeyIdentifier=pek2["arn"],
        VerificationAttributes={"VisaPin": {"PinVerificationKeyIndex": 1, "VerificationValue": pvv}},
        EncryptedPinBlock=block1,
        PrimaryAccountNumber=PAN,
        PinBlockFormat="ISO_FORMAT_3",
    )
    assert ver["VerificationKeyArn"] == pvk["arn"], f"expected verification to report PVK {pvk['arn']}, got {ver['VerificationKeyArn']}"
    assert ver["EncryptionKeyArn"] == pek2["arn"], f"expected verification to report PEK2 {pek2['arn']}, got {ver['EncryptionKeyArn']}"

    # Negative control: the same translated block, under the same keys, rejects a
    # tampered PVV — proving the prior success actually checked the PIN and is not
    # a rubber stamp that any EncryptedPinBlock/VerificationValue pair would pass.
    wrong_digit = "1" if pvv[0] != "1" else "2"
    wrong_pvv = wrong_digit + pvv[1:]
    assert wrong_pvv != pvv, f"tampered pvv fixture collided with genuine pvv {pvv}"

    err = _client_error(
        lambda: data.verify_pin_data(
            VerificationKeyIdentifier=pvk["arn"],
            EncryptionKeyIdentifier=pek2["arn"],
            VerificationAttributes={
                "VisaPin": {"PinVerificationKeyIndex": 1, "VerificationValue": wrong_pvv}
            },
            EncryptedPinBlock=block1,
            PrimaryAccountNumber=PAN,
            PinBlockFormat="ISO_FORMAT_3",
        )
    )
    assert err is not None, "verify_pin_data with a tampered PVV against the translated block was expected to raise"
    assert err.response["Error"]["Code"] == "VerificationFailedException", (
        f"expected VerificationFailedException for a tampered PVV, got {err.response['Error']}"
    )
    assert err.response.get("Reason") == "INVALID_PIN", f"expected Reason=INVALID_PIN, got {err.response.get('Reason')}"
    msg = err.response["Error"]["Message"]
    assert msg == "Pin block verification failed.", (
        f"expected message 'Pin block verification failed.', got {msg!r}"
    )


def _client_error(fn):
    try:
        fn()
    except ClientError as err:
        return err
    return None


def _create_key(ctx, key_usage, modes):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_2KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": key_usage,
            "KeyModesOfUse": modes,
        },
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
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
