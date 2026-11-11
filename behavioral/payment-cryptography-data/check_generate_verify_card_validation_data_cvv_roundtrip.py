"""generate-verify-card-validation-data-cvv-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "generate-verify-card-validation-data-cvv-roundtrip"
GROUP = "data-plane"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CVK generates a CVV (CardVerificationValue1) for a PAN/expiry/service-code
    triple, and VerifyCardValidationData accepts that exact value as valid."""
    key = _create_cvk(ctx)
    data = ctx.client("payment-cryptography-data")
    gen_attrs = {"CardVerificationValue1": {"CardExpiryDate": "1127", "ServiceCode": "121"}}

    gen = data.generate_card_validation_data(
        KeyIdentifier=key["arn"],
        PrimaryAccountNumber=PAN,
        GenerationAttributes=gen_attrs,
    )
    assert gen["KeyArn"] == key["arn"], f"expected KeyArn {key['arn']!r}, got {gen['KeyArn']!r}"
    assert gen["KeyCheckValue"] == key["kcv"], (
        f"expected KeyCheckValue {key['kcv']!r} from the control-plane key, got {gen['KeyCheckValue']!r}"
    )
    validation_data = gen["ValidationData"]
    assert validation_data.isdigit(), f"expected an all-digit CVV, got {validation_data!r}"
    assert len(validation_data) == 3, (
        f"expected the default ValidationDataLength of 3 digits, got {len(validation_data)}: {validation_data!r}"
    )

    ver = data.verify_card_validation_data(
        KeyIdentifier=key["arn"],
        PrimaryAccountNumber=PAN,
        VerificationAttributes=gen_attrs,
        ValidationData=validation_data,
    )
    assert ver["KeyArn"] == key["arn"], f"expected KeyArn {key['arn']!r}, got {ver['KeyArn']!r}"
    assert ver["KeyCheckValue"] == key["kcv"], (
        f"expected KeyCheckValue {key['kcv']!r} from the control-plane key, got {ver['KeyCheckValue']!r}"
    )


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
