"""generate-verify-mac-hmac-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "generate-verify-mac-hmac-roundtrip"
GROUP = "data-plane"
SERVICES = ["payment-cryptography-data"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An HMAC-SHA256 MAC key generates a MAC over message data that then verifies
    successfully via VerifyMac, and the key metadata in both responses matches."""
    key = _create_mac_key(ctx)
    data = ctx.client("payment-cryptography-data")
    message = "3b313038383439303031303733393431353d323430383232363030303733"

    gen = data.generate_mac(
        KeyIdentifier=key["arn"],
        MessageData=message,
        GenerationAttributes={"Algorithm": "HMAC"},
    )
    assert gen["KeyArn"] == key["arn"], f"expected KeyArn {key['arn']!r}, got {gen['KeyArn']!r}"
    assert gen["KeyCheckValue"] == key["kcv"], (
        f"expected KeyCheckValue {key['kcv']!r}, got {gen['KeyCheckValue']!r}"
    )
    assert len(gen["Mac"]) == 64, (
        f"HMAC_SHA256 has no truncation attribute, so GenerateMac must return the full "
        f"32-byte (64 hex-char) MAC; got {len(gen['Mac'])} chars: {gen['Mac']!r}"
    )

    ver = data.verify_mac(
        KeyIdentifier=key["arn"],
        MessageData=message,
        Mac=gen["Mac"],
        VerificationAttributes={"Algorithm": "HMAC"},
    )
    assert ver["KeyArn"] == key["arn"], f"expected KeyArn {key['arn']!r}, got {ver['KeyArn']!r}"
    assert ver["KeyCheckValue"] == key["kcv"], (
        f"expected KeyCheckValue {key['kcv']!r}, got {ver['KeyCheckValue']!r}"
    )


def _create_mac_key(ctx):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "HMAC_SHA256",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": "TR31_M7_HMAC_KEY",
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
