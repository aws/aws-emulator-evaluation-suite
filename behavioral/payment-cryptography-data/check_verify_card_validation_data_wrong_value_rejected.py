"""verify-card-validation-data-wrong-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-card-validation-data-wrong-value-rejected"
GROUP = "verification-semantics"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """VerifyCardValidationData rejects a CVV that does not match the value computed
    from the PAN/expiry/service-code and the CVK, while the correct CVV (positive
    control, computed in the same call chain) verifies cleanly."""
    key = _create_cvk(ctx)
    data = ctx.client("payment-cryptography-data")
    gen_attrs = {"CardVerificationValue1": {"CardExpiryDate": "1127", "ServiceCode": "121"}}

    correct = data.generate_card_validation_data(
        KeyIdentifier=key["arn"], PrimaryAccountNumber=PAN, GenerationAttributes=gen_attrs
    )["ValidationData"]

    # Positive control: the correct value verifies without error.
    data.verify_card_validation_data(
        KeyIdentifier=key["arn"],
        PrimaryAccountNumber=PAN,
        VerificationAttributes=gen_attrs,
        ValidationData=correct,
    )

    # Corrupt exactly one digit, keeping length/format valid.
    wrong_digit = "1" if correct[0] != "1" else "2"
    wrong = wrong_digit + correct[1:]
    assert wrong != correct, f"corruption produced no change: correct={correct!r}"

    err = _client_error(
        lambda: data.verify_card_validation_data(
            KeyIdentifier=key["arn"],
            PrimaryAccountNumber=PAN,
            VerificationAttributes=gen_attrs,
            ValidationData=wrong,
        )
    )
    assert err is not None, "expected VerifyCardValidationData to reject a wrong CVV, it succeeded"
    assert err.response["Error"]["Code"] == "VerificationFailedException", (
        f"expected error code VerificationFailedException, got {err.response['Error']['Code']!r}"
    )
    assert err.response.get("Reason") == "INVALID_VALIDATION_DATA", (
        f"expected Reason INVALID_VALIDATION_DATA, got {err.response.get('Reason')!r}"
    )
    msg = err.response["Error"]["Message"]
    assert msg == "Card validation data verification failed.", (
        f"expected message 'Card validation data verification failed.', got {msg!r}"
    )


def _client_error(fn):
    try:
        fn()
    except ClientError as err:
        return err
    return None


def _create_cvk(ctx):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_2KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": "TR31_C0_CARD_VERIFICATION_KEY",
            "KeyModesOfUse": {"Generate": True, "Verify": True},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
