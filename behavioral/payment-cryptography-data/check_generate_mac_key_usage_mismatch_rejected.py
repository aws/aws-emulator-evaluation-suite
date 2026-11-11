"""generate-mac-key-usage-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generate-mac-key-usage-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography-data"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateMac with a TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY is rejected with ValidationException and
    its exact message, while the same call with a TR31_M7_HMAC_KEY succeeds."""
    mac_key = _create_key(
        ctx, "HMAC_SHA256", "TR31_M7_HMAC_KEY", {"Generate": True, "Verify": True}
    )
    wrong_key = _create_key(
        ctx, "TDES_2KEY", "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    )
    data = ctx.client("payment-cryptography-data")
    message = "313032333034303530363037"

    data.generate_mac(
        KeyIdentifier=mac_key["arn"],
        MessageData=message,
        GenerationAttributes={"Algorithm": "HMAC"},
    )

    err = _client_error(
        lambda: data.generate_mac(
            KeyIdentifier=wrong_key["arn"],
            MessageData=message,
            GenerationAttributes={"Algorithm": "HMAC"},
        )
    )
    assert err is not None, "GenerateMac with a TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY succeeded; expected rejection"
    code = err.response["Error"]["Code"]
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    msg = err.response["Error"]["Message"]
    expected = (
        "Invalid key with KeyAlgorithm HMAC used with MacAlgorithm TDES_2KEY. "
        "Please use valid HMAC Key."
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _client_error(fn):
    try:
        fn()
    except ClientError as err:
        return err
    return None


def _create_key(ctx, key_algorithm, key_usage, modes):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": key_algorithm,
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
