"""generate-verify-card-validation-data-cvv2-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "generate-verify-card-validation-data-cvv2-roundtrip"
GROUP = "data-plane"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CVK generates a CVV2 (CardVerificationValue2, keyed only on PAN + expiry --
    no service code) and VerifyCardValidationData accepts that exact value, and the
    CVV2 differs from a CVV1 computed for the same card under the same key."""
    key = _create_cvk(ctx)
    data = ctx.client("payment-cryptography-data")
    cvv2_attrs = {"CardVerificationValue2": {"CardExpiryDate": "1127"}}
    cvv1_attrs = {"CardVerificationValue1": {"CardExpiryDate": "1127", "ServiceCode": "121"}}

    cvv2 = data.generate_card_validation_data(
        KeyIdentifier=key["arn"], PrimaryAccountNumber=PAN, GenerationAttributes=cvv2_attrs
    )["ValidationData"]
    cvv1 = data.generate_card_validation_data(
        KeyIdentifier=key["arn"], PrimaryAccountNumber=PAN, GenerationAttributes=cvv1_attrs
    )["ValidationData"]
    assert cvv2 != cvv1, f"CVV2 {cvv2!r} must differ from CVV1 {cvv1!r} (service code changes the derivation)"

    ver = data.verify_card_validation_data(
        KeyIdentifier=key["arn"],
        PrimaryAccountNumber=PAN,
        VerificationAttributes=cvv2_attrs,
        ValidationData=cvv2,
    )
    assert ver["KeyArn"] == key["arn"], f"expected KeyArn {key['arn']!r} echoed on successful verify, got {ver['KeyArn']!r}"


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
