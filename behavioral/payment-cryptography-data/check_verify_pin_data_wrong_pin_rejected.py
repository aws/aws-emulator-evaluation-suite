"""verify-pin-data-wrong-pin-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-pin-data-wrong-pin-rejected"
GROUP = "verification-semantics"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """VerifyPinData rejects a Visa PVV that does not match the encrypted PIN block,
    while the genuine PVV computed by GeneratePinData (positive control) verifies."""
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
    pvv = gen["PinData"]["VerificationValue"]
    block = gen["EncryptedPinBlock"]

    # Positive control: the genuine PVV verifies.
    data.verify_pin_data(
        VerificationKeyIdentifier=pvk["arn"],
        EncryptionKeyIdentifier=pek["arn"],
        VerificationAttributes={"VisaPin": {"PinVerificationKeyIndex": 1, "VerificationValue": pvv}},
        EncryptedPinBlock=block,
        PrimaryAccountNumber=PAN,
        PinBlockFormat="ISO_FORMAT_0",
    )

    wrong_digit = "1" if pvv[0] != "1" else "2"
    wrong_pvv = wrong_digit + pvv[1:]
    assert wrong_pvv != pvv, f"tampering produced an unchanged PVV: {wrong_pvv!r}"

    err = _client_error(
        lambda: data.verify_pin_data(
            VerificationKeyIdentifier=pvk["arn"],
            EncryptionKeyIdentifier=pek["arn"],
            VerificationAttributes={
                "VisaPin": {"PinVerificationKeyIndex": 1, "VerificationValue": wrong_pvv}
            },
            EncryptedPinBlock=block,
            PrimaryAccountNumber=PAN,
            PinBlockFormat="ISO_FORMAT_0",
        )
    )
    assert err is not None, f"expected VerifyPinData to reject wrong PVV {wrong_pvv!r}, but it succeeded"
    assert err.response["Error"]["Code"] == "VerificationFailedException", (
        f'expected error code "VerificationFailedException", got '
        f'{err.response["Error"]["Code"]!r}'
    )
    assert err.response.get("Reason") == "INVALID_PIN", (
        f'expected Reason "INVALID_PIN", got {err.response.get("Reason")!r}'
    )
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
    tag_value = ctx.unique_name("sim2real-val-")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_2KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": key_usage,
            "KeyModesOfUse": modes,
        },
        Tags=[{"Key": "sim2real-env", "Value": tag_value}],
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
