"""generate-verify-pin-data-visa-pvv-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "generate-verify-pin-data-visa-pvv-roundtrip"
GROUP = "data-plane"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GeneratePinData derives a random PIN, its encrypted PIN block under a PEK, and
    the matching Visa PVV under a PVK; VerifyPinData then confirms that the encrypted
    PIN block and PVV are mutually consistent."""
    pvk = _create_key(ctx, "TR31_V2_VISA_PIN_VERIFICATION_KEY", {"Generate": True, "Verify": True})
    pek = _create_key(
        ctx, "TR31_P0_PIN_ENCRYPTION_KEY",
        {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    )
    data = ctx.client("payment-cryptography-data")

    gen = data.generate_pin_data(
        GenerationKeyIdentifier=pvk["arn"],
        EncryptionKeyIdentifier=pek["arn"],
        PrimaryAccountNumber=PAN,
        PinBlockFormat="ISO_FORMAT_0",
        GenerationAttributes={"VisaPin": {"PinVerificationKeyIndex": 1}},
    )
    assert gen["GenerationKeyArn"] == pvk["arn"]
    assert gen["EncryptionKeyArn"] == pek["arn"]
    pvv = gen["PinData"]["VerificationValue"]
    block = gen["EncryptedPinBlock"]

    ver = data.verify_pin_data(
        VerificationKeyIdentifier=pvk["arn"],
        EncryptionKeyIdentifier=pek["arn"],
        VerificationAttributes={"VisaPin": {"PinVerificationKeyIndex": 1, "VerificationValue": pvv}},
        EncryptedPinBlock=block,
        PrimaryAccountNumber=PAN,
        PinBlockFormat="ISO_FORMAT_0",
    )
    assert ver["VerificationKeyArn"] == pvk["arn"]
    assert ver["EncryptionKeyArn"] == pek["arn"]


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
