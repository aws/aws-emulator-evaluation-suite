"""decapsulate-ciphertext-wrong-length-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decapsulate-ciphertext-wrong-length-rejected"
GROUP = "errors"
SERVICES = ["kms"]

ERR_INVALID_CIPHERTEXT = "InvalidCiphertextException"


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
    """Decapsulate with a correctly-sized ciphertext recovers the shared secret (positive
    control); truncating it to a length inconsistent with the key's ML-KEM spec raises
    InvalidCiphertextException."""
    kms = ctx.client("kms")
    key_meta = kms.create_key(
        Description=ctx.unique_name("kms-ml-kem-"),
        KeyUsage="ENCAPSULATE_DECAPSULATE",
        KeySpec="ML_KEM_768",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-decapsulate-ciphertext-wrong-length-rejected"}],
    )["KeyMetadata"]
    key_id = key_meta["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    encapsulated = kms.encapsulate(KeyId=key_id, EncapsulationAlgorithm="ML_KEM")
    ciphertext = encapsulated["SharedSecretCiphertextBlob"]

    control = kms.decapsulate(
        KeyId=key_id, SharedSecretCiphertextBlob=ciphertext, EncapsulationAlgorithm="ML_KEM"
    )
    assert control["SharedSecret"] == encapsulated["SharedSecret"], (
        "positive control: decapsulating the matching ciphertext must recover the shared secret"
    )

    truncated = ciphertext[:-1]
    code, message = _error(
        lambda: kms.decapsulate(
            KeyId=key_id, SharedSecretCiphertextBlob=truncated, EncapsulationAlgorithm="ML_KEM"
        )
    )
    assert code == ERR_INVALID_CIPHERTEXT, f"Expected {ERR_INVALID_CIPHERTEXT}, got {code!r}"
    expected = (
        "SharedSecretCiphertextBlob length mismatch for ML_KEM_768 KeySpec: "
        f"expected {len(ciphertext)} bytes, got {len(truncated)} bytes."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
