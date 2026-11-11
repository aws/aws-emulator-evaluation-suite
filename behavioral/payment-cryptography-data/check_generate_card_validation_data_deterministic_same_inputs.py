"""generate-card-validation-data-deterministic-same-inputs."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "generate-card-validation-data-deterministic-same-inputs"
GROUP = "data-plane"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateCardValidationData returns the same ValidationData for identical inputs and a different
    value for a different input, and VerifyCardValidationData accepts both against their own inputs."""
    key = _create_cvk(ctx)
    data = ctx.client("payment-cryptography-data")
    gen_attrs = {"CardVerificationValue1": {"CardExpiryDate": "0930", "ServiceCode": "201"}}
    other_attrs = {"CardVerificationValue1": {"CardExpiryDate": "1231", "ServiceCode": "999"}}

    first = data.generate_card_validation_data(
        KeyIdentifier=key["arn"], PrimaryAccountNumber=PAN, GenerationAttributes=gen_attrs
    )["ValidationData"]
    second = data.generate_card_validation_data(
        KeyIdentifier=key["arn"], PrimaryAccountNumber=PAN, GenerationAttributes=gen_attrs
    )["ValidationData"]
    assert first == second, f"same inputs produced different ValidationData: {first!r} != {second!r}"

    other = data.generate_card_validation_data(
        KeyIdentifier=key["arn"], PrimaryAccountNumber=PAN, GenerationAttributes=other_attrs
    )["ValidationData"]
    assert other != first, (
        f"different (expiry, service code) inputs produced the same ValidationData "
        f"{other!r} == {first!r}; the value does not depend on its inputs"
    )

    ver_first = data.verify_card_validation_data(
        KeyIdentifier=key["arn"],
        PrimaryAccountNumber=PAN,
        VerificationAttributes=gen_attrs,
        ValidationData=first,
    )
    assert ver_first["KeyArn"] == key["arn"], "independent Verify of the first value did not accept it"

    ver_other = data.verify_card_validation_data(
        KeyIdentifier=key["arn"],
        PrimaryAccountNumber=PAN,
        VerificationAttributes=other_attrs,
        ValidationData=other,
    )
    assert ver_other["KeyArn"] == key["arn"], "independent Verify of the second value did not accept it"


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
