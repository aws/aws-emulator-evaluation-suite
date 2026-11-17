"""encapsulate-decapsulate-invalid-key-usage-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encapsulate-decapsulate-invalid-key-usage-rejected"
GROUP = "errors"
SERVICES = ["kms"]

ERR_INVALID_KEY_USAGE = "InvalidKeyUsageException"


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
    """Positive control: Encapsulate succeeds against an ENCAPSULATE_DECAPSULATE key. Encapsulate
    and Decapsulate against a key whose usage is ENCRYPT_DECRYPT raise InvalidKeyUsageException."""
    kms = ctx.client("kms")

    control_key = kms.create_key(
        Description=ctx.unique_name("kms-ml-kem-control-"),
        KeyUsage="ENCAPSULATE_DECAPSULATE",
        KeySpec="ML_KEM_768",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-encapsulate-decapsulate-invalid-key-usage"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda _k=control_key["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    control_resp = kms.encapsulate(KeyId=control_key["KeyId"], EncapsulationAlgorithm="ML_KEM")
    assert control_resp["SharedSecretCiphertextBlob"], (
        "positive control: Encapsulate with an ENCAPSULATE_DECAPSULATE key must produce a ciphertext"
    )

    wrong_usage_key = kms.create_key(
        Description=ctx.unique_name("kms-encrypt-decrypt-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-encapsulate-decapsulate-invalid-key-usage"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda _k=wrong_usage_key["KeyId"]: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    key_arn = wrong_usage_key["Arn"]

    code, message = _error(
        lambda: kms.encapsulate(KeyId=wrong_usage_key["KeyId"], EncapsulationAlgorithm="ML_KEM")
    )
    assert code == ERR_INVALID_KEY_USAGE, f"Expected {ERR_INVALID_KEY_USAGE}, got {code!r}"
    expected = f"{key_arn} key usage is ENCRYPT_DECRYPT which is not valid for Encapsulate."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(
        lambda: kms.decapsulate(
            KeyId=wrong_usage_key["KeyId"],
            SharedSecretCiphertextBlob=control_resp["SharedSecretCiphertextBlob"],
            EncapsulationAlgorithm="ML_KEM",
        )
    )
    assert code == ERR_INVALID_KEY_USAGE, f"Expected {ERR_INVALID_KEY_USAGE}, got {code!r}"
    expected = f"{key_arn} key usage is ENCRYPT_DECRYPT which is not valid for Decapsulate."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
