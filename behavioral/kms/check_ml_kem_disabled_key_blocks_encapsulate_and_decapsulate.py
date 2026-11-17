"""ml-kem-disabled-key-blocks-encapsulate-and-decapsulate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ml-kem-disabled-key-blocks-encapsulate-and-decapsulate"
GROUP = "errors"
SERVICES = ["kms"]

ERR_DISABLED = "DisabledException"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encapsulate and Decapsulate succeed on an enabled ML-KEM key; disabling the key rejects
    both calls with DisabledException while the key stays disabled, and re-enabling restores
    the identical calls to success."""
    kms = ctx.client("kms")
    key_meta = kms.create_key(
        Description=ctx.unique_name("kms-ml-kem-"),
        KeyUsage="ENCAPSULATE_DECAPSULATE",
        KeySpec="ML_KEM_768",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-ml-kem-disabled-key-blocks-encapsulate-decapsulate"}],
    )["KeyMetadata"]
    key_id, key_arn = key_meta["KeyId"], key_meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    encapsulated = kms.encapsulate(KeyId=key_id, EncapsulationAlgorithm="ML_KEM")
    ciphertext = encapsulated["SharedSecretCiphertextBlob"]
    decapsulated = kms.decapsulate(
        KeyId=key_id, SharedSecretCiphertextBlob=ciphertext, EncapsulationAlgorithm="ML_KEM"
    )
    assert decapsulated["SharedSecret"] == encapsulated["SharedSecret"], (
        "positive control: Decapsulate must recover the matching shared secret while the key is enabled"
    )

    kms.disable_key(KeyId=key_id)
    assert kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Disabled"

    code, message = _error(lambda: kms.encapsulate(KeyId=key_id, EncapsulationAlgorithm="ML_KEM"))
    assert code == ERR_DISABLED, f"Expected {ERR_DISABLED}, got {code!r}"
    assert message == f"{key_arn} is disabled.", f"unexpected message: {message!r}"

    code, message = _error(
        lambda: kms.decapsulate(
            KeyId=key_id, SharedSecretCiphertextBlob=ciphertext, EncapsulationAlgorithm="ML_KEM"
        )
    )
    assert code == ERR_DISABLED, f"Expected {ERR_DISABLED}, got {code!r}"
    assert message == f"{key_arn} is disabled.", f"unexpected message: {message!r}"
    assert kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Disabled"

    kms.enable_key(KeyId=key_id)
    assert kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Enabled"
    restored = kms.encapsulate(KeyId=key_id, EncapsulationAlgorithm="ML_KEM")
    restored_ciphertext = restored["SharedSecretCiphertextBlob"]
    restored_decap = kms.decapsulate(
        KeyId=key_id, SharedSecretCiphertextBlob=restored_ciphertext, EncapsulationAlgorithm="ML_KEM"
    )
    assert restored_decap["SharedSecret"] == restored["SharedSecret"], (
        "re-enabling the key must restore Encapsulate/Decapsulate to success"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
