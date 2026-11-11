"""export-import-tr31-key-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "export-import-tr31-key-roundtrip"
GROUP = "data-plane"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExportKey wraps a data key's real key material under a KEK using TR-31, and ImportKey
    unwraps that exact block back into a new key whose KeyCheckValue and KeyAttributes match
    the original -- proving the emulator performs real TR-31 cryptography, not a stub."""
    pc = ctx.client("payment-cryptography")

    kek_attributes = {
        "KeyUsage": "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    kek = pc.create_key(KeyAttributes=kek_attributes, Exportable=True)["Key"]
    kek_arn = kek["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, kek_arn))

    data_key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    data_key = pc.create_key(KeyAttributes=data_key_attributes, Exportable=True)["Key"]
    data_key_arn = data_key["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, data_key_arn))

    exported = pc.export_key(
        ExportKeyIdentifier=data_key_arn,
        KeyMaterial={"Tr31KeyBlock": {"WrappingKeyIdentifier": kek_arn}},
    )["WrappedKey"]
    assert exported["KeyCheckValue"] == data_key["KeyCheckValue"], (
        f"exported KeyCheckValue {exported['KeyCheckValue']!r} != "
        f"source {data_key['KeyCheckValue']!r}"
    )
    assert exported["WrappedKeyMaterialFormat"] == "TR31_KEY_BLOCK", (
        f"WrappedKeyMaterialFormat: {exported['WrappedKeyMaterialFormat']!r}"
    )
    wrapped_block = exported["KeyMaterial"]
    assert len(wrapped_block) >= 56, f"wrapped TR-31 block too short: {len(wrapped_block)} chars"

    imported = pc.import_key(
        KeyMaterial={
            "Tr31KeyBlock": {
                "WrappingKeyIdentifier": kek_arn,
                "WrappedKeyBlock": wrapped_block,
            }
        }
    )["Key"]
    imported_arn = imported["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, imported_arn))
    assert imported_arn != data_key_arn, f"import minted no new key: {imported_arn}"

    # terminal read: an independent GetKey, not the ImportKey response that just created it
    fetched = pc.get_key(KeyIdentifier=imported_arn)["Key"]
    assert fetched["KeyOrigin"] == "EXTERNAL", f"KeyOrigin: {fetched['KeyOrigin']!r}"
    assert fetched["KeyState"] == "CREATE_COMPLETE", f"KeyState: {fetched['KeyState']!r}"
    assert fetched["KeyCheckValue"] == data_key["KeyCheckValue"], (
        f"KeyCheckValue mismatch after roundtrip: {fetched['KeyCheckValue']!r} "
        f"!= {data_key['KeyCheckValue']!r}"
    )
    expected_attrs = _full_modes(data_key_attributes)
    assert fetched["KeyAttributes"] == expected_attrs, (
        f"KeyAttributes mismatch after roundtrip: {fetched['KeyAttributes']!r} != {expected_attrs!r}"
    )


def _full_modes(key_attributes: dict) -> dict:
    """GetKey/CreateKey/ImportKey always echo back the complete KeyModesOfUse struct (all 9
    boolean fields), not just the ones the caller set to True -- normalize for comparison."""
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
