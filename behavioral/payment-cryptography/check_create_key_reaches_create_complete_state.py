"""create-key-reaches-create-complete-state."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-key-reaches-create-complete-state"
GROUP = "state"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKey synchronously lands in CREATE_COMPLETE with AWS-origin metadata and echoes
    back the immutable KeyAttributes exactly, and GetKey agrees with the create response."""
    pc = ctx.client("payment-cryptography")
    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    created = pc.create_key(
        KeyAttributes=key_attributes,
        Exportable=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Key"]
    arn = created["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))

    assert created["KeyState"] == "CREATE_COMPLETE", (
        f"expected CreateKey to land synchronously in CREATE_COMPLETE, got {created['KeyState']!r}"
    )
    assert created["KeyOrigin"] == "AWS_PAYMENT_CRYPTOGRAPHY", (
        f"expected an AWS-generated key to report origin AWS_PAYMENT_CRYPTOGRAPHY, "
        f"got {created['KeyOrigin']!r}"
    )
    assert created["Enabled"] is True, (
        f"expected a freshly created key to be enabled, got {created['Enabled']!r}"
    )
    assert created["Exportable"] is True, (
        f"expected Exportable=True to round-trip, got {created['Exportable']!r}"
    )
    assert created["KeyAttributes"] == _full_modes(key_attributes), (
        f"expected KeyAttributes to echo back with all KeyModesOfUse fields filled in, "
        f"got {created['KeyAttributes']!r}"
    )
    assert len(created["KeyCheckValue"]) >= 4, (
        f"expected a non-trivial KeyCheckValue, got {created['KeyCheckValue']!r}"
    )

    fetched = pc.get_key(KeyIdentifier=arn)["Key"]
    assert fetched["KeyArn"] == arn, (
        f"expected GetKey to resolve the same ARN, got {fetched['KeyArn']!r}"
    )
    assert fetched["KeyState"] == "CREATE_COMPLETE", (
        f"expected GetKey to agree the key is CREATE_COMPLETE, got {fetched['KeyState']!r}"
    )
    assert fetched["KeyAttributes"] == _full_modes(key_attributes), (
        f"expected GetKey's KeyAttributes to match CreateKey's, got {fetched['KeyAttributes']!r}"
    )
    assert fetched["KeyCheckValue"] == created["KeyCheckValue"], (
        f"expected GetKey's KeyCheckValue to match CreateKey's "
        f"({created['KeyCheckValue']!r}), got {fetched['KeyCheckValue']!r}"
    )


def _full_modes(key_attributes: dict) -> dict:
    """GetKey/CreateKey always echo back the complete KeyModesOfUse struct (all 9 boolean
    fields), not just the ones the caller set to True -- normalize for comparison."""
    all_fields = (
        "Decrypt",
        "DeriveKey",
        "Encrypt",
        "Generate",
        "NoRestrictions",
        "Sign",
        "Unwrap",
        "Verify",
        "Wrap",
    )
    given = key_attributes["KeyModesOfUse"]
    full = {"KeyModesOfUse": {f: given.get(f, False) for f in all_fields}}
    return {**key_attributes, **full}


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
