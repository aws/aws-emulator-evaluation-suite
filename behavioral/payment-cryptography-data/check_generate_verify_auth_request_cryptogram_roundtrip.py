"""generate-verify-auth-request-cryptogram-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "generate-verify-auth-request-cryptogram-roundtrip"
GROUP = "data-plane"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"
TRANSACTION_DATA = "00112233445566778899AABBCCDDEEFF"


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateAuthRequestCryptogram derives an EMV ARQC from an IMK-AC key and EMV2000
    session-key derivation attributes; VerifyAuthRequestCryptogram then independently
    re-derives the session key and confirms the exact same ARQC is valid."""
    key = _create_imk_ac(ctx)
    data = ctx.client("payment-cryptography-data")
    session_attrs = {
        "Emv2000": {
            "PrimaryAccountNumber": PAN,
            "PanSequenceNumber": "00",
            "ApplicationTransactionCounter": "0001",
        }
    }

    gen = data.generate_auth_request_cryptogram(
        KeyIdentifier=key["arn"],
        TransactionData=TRANSACTION_DATA,
        MajorKeyDerivationMode="EMV_OPTION_A",
        SessionKeyDerivationAttributes=session_attrs,
    )
    assert gen["KeyArn"] == key["arn"], f"expected KeyArn {key['arn']!r} echoed on generate, got {gen['KeyArn']!r}"
    assert gen["KeyCheckValue"] == key["kcv"], f"expected KCV {key['kcv']!r} on generate, got {gen['KeyCheckValue']!r}"
    arqc = gen["AuthRequestCryptogram"]
    assert len(arqc) == 16, f"expected a 16-hex-char ARQC, got {arqc!r} (len {len(arqc)})"

    ver = data.verify_auth_request_cryptogram(
        KeyIdentifier=key["arn"],
        TransactionData=TRANSACTION_DATA,
        AuthRequestCryptogram=arqc,
        MajorKeyDerivationMode="EMV_OPTION_A",
        SessionKeyDerivationAttributes=session_attrs,
    )
    assert ver["KeyArn"] == key["arn"], f"expected KeyArn {key['arn']!r} echoed on successful verify, got {ver['KeyArn']!r}"
    assert ver["KeyCheckValue"] == key["kcv"], f"expected KCV {key['kcv']!r} on verify, got {ver['KeyCheckValue']!r}"


def _create_imk_ac(ctx):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_2KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
            "KeyModesOfUse": {"DeriveKey": True},
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
