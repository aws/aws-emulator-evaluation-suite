"""export-key-not-exportable-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "export-key-not-exportable-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportKey on an Exportable=False key gets ValidationException with its exact message and the key
    stays non-exportable, while an Exportable=True key exports wrapped material that imports back with
    the same KeyCheckValue."""
    pc = ctx.client("payment-cryptography")
    resource_tags = [{"Key": "sim2real", "Value": "1"}]

    kek_attributes = {
        "KeyUsage": "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    kek = pc.create_key(KeyAttributes=kek_attributes, Exportable=True, Tags=resource_tags)["Key"]
    kek_arn = kek["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, kek_arn))

    data_key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    non_exportable = pc.create_key(
        KeyAttributes=data_key_attributes, Exportable=False, Tags=resource_tags
    )["Key"]
    non_exportable_arn = non_exportable["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, non_exportable_arn))

    error = _client_error(
        lambda: pc.export_key(
            ExportKeyIdentifier=non_exportable_arn,
            KeyMaterial={"Tr31KeyBlock": {"WrappingKeyIdentifier": kek_arn}},
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"ExportKey on a non-exportable key returned {error!r}, expected "
        f"'ValidationException'"
    )
    expected_message = f"Export is not enabled for the key {non_exportable_arn}."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    still_not_exportable = pc.get_key(KeyIdentifier=non_exportable_arn)["Key"]
    assert still_not_exportable["Exportable"] is False, (
        f"the non-exportable key's Exportable flag became "
        f"{still_not_exportable['Exportable']!r} after a rejected ExportKey call"
    )

    # positive control: an exportable twin key can actually be exported
    exportable = pc.create_key(
        KeyAttributes=data_key_attributes, Exportable=True, Tags=resource_tags
    )["Key"]
    exportable_arn = exportable["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, exportable_arn))
    wrapped = pc.export_key(
        ExportKeyIdentifier=exportable_arn,
        KeyMaterial={"Tr31KeyBlock": {"WrappingKeyIdentifier": kek_arn}},
    )["WrappedKey"]
    assert wrapped["KeyCheckValue"] == exportable["KeyCheckValue"], (
        f"exported KeyCheckValue {wrapped['KeyCheckValue']!r} does not match the source key's "
        f"{exportable['KeyCheckValue']!r}"
    )

    # independent read at the destination: import the wrapped block back through a DIFFERENT
    # operation than the one that produced it, and confirm it carries real, usable key material
    # rather than an opaque blob that merely echoes the source's own reported KeyCheckValue.
    imported = pc.import_key(
        KeyMaterial={
            "Tr31KeyBlock": {
                "WrappingKeyIdentifier": kek_arn,
                "WrappedKeyBlock": wrapped["KeyMaterial"],
            }
        }
    )["Key"]
    imported_arn = imported["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, imported_arn))
    assert imported["KeyCheckValue"] == exportable["KeyCheckValue"], (
        f"re-importing the exported wrapped block produced KeyCheckValue "
        f"{imported['KeyCheckValue']!r}, expected {exportable['KeyCheckValue']!r} -- the "
        f"exported material is not the real key"
    )


def _client_error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"ExportKey on a non-exportable key was expected to raise ValidationException, but it "
        f"SUCCEEDED and returned {result!r}"
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
