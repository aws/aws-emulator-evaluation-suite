"""get-parameters-for-import-native-origin-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-parameters-for-import-native-origin-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """GetParametersForImport on an AWS_KMS-origin key fails with UnsupportedOperationException.
    The key stays Enabled and usable, and the same call succeeds on an Origin=EXTERNAL key."""
    kms = ctx.client("kms")

    native_key = kms.create_key(
        Origin="AWS_KMS",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Description=ctx.unique_name("sim2real-native-origin-import-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-get-parameters-for-import-native-origin-key-rejected"}],
    )
    native_key_id = native_key["KeyMetadata"]["KeyId"]
    native_key_arn = native_key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: _best_effort_schedule_deletion(kms, native_key_id)
    )
    assert native_key["KeyMetadata"]["Origin"] == "AWS_KMS", native_key["KeyMetadata"]["Origin"]
    assert native_key["KeyMetadata"]["KeyState"] == "Enabled", native_key["KeyMetadata"]["KeyState"]

    code, message = _error(
        lambda: kms.get_parameters_for_import(
            KeyId=native_key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
        )
    )
    assert code == "UnsupportedOperationException", f"GetParametersForImport on AWS_KMS-origin key -> got {code}"
    assert message == f"{native_key_arn} origin is AWS_KMS which is not valid for this operation.", (
        f"unexpected message: {message!r}"
    )

    # The rejected call must not flip the key to EXTERNAL/PendingImport as a side effect.
    after_reject = kms.describe_key(KeyId=native_key_id)["KeyMetadata"]
    assert after_reject["Origin"] == "AWS_KMS", after_reject["Origin"]
    assert after_reject["KeyState"] == "Enabled", after_reject["KeyState"]
    plaintext = b"sim2real-kms-native-origin-still-usable"
    ciphertext = kms.encrypt(KeyId=native_key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(KeyId=native_key_id, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"expected {plaintext!r}, got {decrypted!r}"

    # Positive control: same call, only Origin differs.
    external_key = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Description=ctx.unique_name("sim2real-external-origin-import-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-get-parameters-for-import-native-origin-key-rejected"}],
    )
    external_key_id = external_key["KeyMetadata"]["KeyId"]
    external_key_arn = external_key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, external_key_id))
    assert external_key["KeyMetadata"]["KeyState"] == "PendingImport", external_key["KeyMetadata"]["KeyState"]

    params = kms.get_parameters_for_import(
        KeyId=external_key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    assert params["KeyId"] == external_key_arn, f"expected {external_key_arn}, got {params['KeyId']}"
    assert params["PublicKey"][:1] == b"\x30", "wrapping public key must be DER encoded"
    assert params["ImportToken"], "an import token must be issued"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _best_effort_schedule_deletion(kms, key_id):
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
