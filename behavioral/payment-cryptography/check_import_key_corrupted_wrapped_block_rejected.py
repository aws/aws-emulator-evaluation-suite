"""import-key-corrupted-wrapped-block-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-key-corrupted-wrapped-block-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportKey of a TR-31 wrapped key block with one payload character flipped gets
    ValidationException with its exact message and creates no key, while the untampered block from
    ExportKey imports with the source key's KeyCheckValue."""
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

    wrapped_block = pc.export_key(
        ExportKeyIdentifier=data_key_arn,
        KeyMaterial={"Tr31KeyBlock": {"WrappingKeyIdentifier": kek_arn}},
    )["WrappedKey"]["KeyMaterial"]

    corrupted_block = _flip_one_char(wrapped_block)
    pre_arns = _list_key_arns(pc)
    error = _client_error(
        lambda: pc.import_key(
            KeyMaterial={
                "Tr31KeyBlock": {
                    "WrappingKeyIdentifier": kek_arn,
                    "WrappedKeyBlock": corrupted_block,
                }
            }
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException importing a one-character-corrupted TR-31 block, got {error!r}"
    )
    expected_message = "KeyBlock data in the imported payload is invalid."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    post_arns = _list_key_arns(pc)
    assert post_arns == pre_arns, (
        f"a rejected corrupted import must create no key; ListKeys shows new arns "
        f"{post_arns - pre_arns!r}"
    )

    # positive control: the original, untampered wrapped block imports cleanly
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

    fetched = pc.get_key(KeyIdentifier=imported_arn)["Key"]
    assert fetched["KeyCheckValue"] == data_key["KeyCheckValue"], (
        f"independent GetKey on the imported key should report the source key's KeyCheckValue "
        f"{data_key['KeyCheckValue']!r}, got {fetched['KeyCheckValue']!r}"
    )


def _flip_one_char(s: str) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    idx = len(s) // 2
    original = s[idx]
    for candidate in alphabet:
        if candidate != original:
            return s[:idx] + candidate + s[idx + 1 :]
    raise AssertionError("could not find a differing character to corrupt the block with")


def _list_key_arns(pc) -> set[str]:
    arns: set[str] = set()
    kwargs: dict = {}
    while True:
        page = pc.list_keys(**kwargs)
        arns.update(k["KeyArn"] for k in page["Keys"])
        token = page.get("NextToken")
        if not token:
            return arns
        kwargs = {"NextToken": token}


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects a corrupted TR-31 wrapped key block, but the call SUCCEEDED and "
        f"returned {result!r}"
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
