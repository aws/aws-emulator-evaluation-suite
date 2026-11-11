"""create-key-invalid-attribute-combo-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-key-invalid-attribute-combo-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKey rejects an asymmetric-signature KeyUsage with a SYMMETRIC_KEY KeyClass and an AES
    algorithm with ValidationException and its exact message, while a coherent combination reaches
    CREATE_COMPLETE and GetKey returns its KeyAttributes."""
    pc = ctx.client("payment-cryptography")

    invalid_attributes = {
        "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Sign": True, "Verify": True},
    }
    error = _client_error(
        lambda: pc.create_key(KeyAttributes=invalid_attributes, Exportable=True)
    )
    assert error.get("Code") == "ValidationException", (
        f'an incoherent (asymmetric-signature KeyUsage + SYMMETRIC_KEY KeyClass + AES '
        f'KeyAlgorithm) combination was rejected with {error.get("Code")!r}, expected '
        f'"ValidationException"'
    )
    expected_message = (
        "KeyAlgorithm AES_128 is not valid for the KeyUsage "
        "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # positive control: a coherent, valid combination is accepted
    valid_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    tag_value = ctx.unique_name("sim2real-val-")
    created = pc.create_key(
        KeyAttributes=valid_attributes,
        Exportable=True,
        Tags=[{"Key": "sim2real-env", "Value": tag_value}],
    )["Key"]
    arn = created["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))
    assert created["KeyState"] == "CREATE_COMPLETE", (
        f'a coherent KeyAttributes combination landed in KeyState {created["KeyState"]!r}, '
        f'expected "CREATE_COMPLETE"'
    )

    # terminal assertion is an independent read, not the mutating call's own response
    fetched = pc.get_key(KeyIdentifier=arn)["Key"]
    assert fetched["KeyState"] == "CREATE_COMPLETE", (
        f'GetKey on the accepted key reported KeyState {fetched["KeyState"]!r}, expected '
        f'"CREATE_COMPLETE"'
    )
    assert fetched["KeyAttributes"] == _full_modes(valid_attributes), (
        f'GetKey echoed KeyAttributes {fetched["KeyAttributes"]!r}, expected '
        f'{_full_modes(valid_attributes)!r}'
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


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


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
