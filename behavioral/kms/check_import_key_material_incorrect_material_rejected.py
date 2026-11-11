"""import-key-material-incorrect-material-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-key-material-incorrect-material-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-importing (EXISTING_KEY_MATERIAL) correctly sized material that differs from the bytes originally
    imported fails with IncorrectKeyMaterialException and the exact message, and the key stays Enabled;
    re-importing the original bytes succeeds."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    key_id = _create_external_key(ctx)
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )

    def _wrap_and_import(material, import_type):
        params = kms.get_parameters_for_import(
            KeyId=key_id,
            WrappingAlgorithm="RSAES_OAEP_SHA_256",
            WrappingKeySpec="RSA_2048",
        )
        public_key = serialization.load_der_public_key(params["PublicKey"])
        wrapped = public_key.encrypt(material, oaep)
        return kms.import_key_material(
            KeyId=key_id,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=wrapped,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
            ImportType=import_type,
        )

    # Initial import: 32 bytes of AES-256 material, establishes the key's material.
    original_material = b"\x22" * 32
    first_import = _wrap_and_import(original_material, "NEW_KEY_MATERIAL")
    state_after_initial = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after_initial == "Enabled", (
        f"expected Enabled after initial import, got {state_after_initial}"
    )

    # Reimport with correctly-SIZED (32-byte) but DIFFERENT material -- this is the
    # documented "material does not match expectations for the KMS key" case.
    mismatched_material = b"\x33" * 32
    code, message = _error(lambda: _wrap_and_import(mismatched_material, "EXISTING_KEY_MATERIAL"))
    assert code == "IncorrectKeyMaterialException", f"expected IncorrectKeyMaterialException, got {code}"
    expected_message = (
        "Imported key material does not have the expected identifier "
        f"({first_import['KeyMaterialId']})."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    state_after_failure = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after_failure == "Enabled", "a rejected reimport must not change the key's state"

    # positive control: reimporting the SAME material that was originally imported succeeds
    _wrap_and_import(original_material, "EXISTING_KEY_MATERIAL")
    state_after_success = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after_success == "Enabled", (
        f"expected Enabled after reimporting the original material, got {state_after_success}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_external_key(ctx):
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-ext-"),
        Origin="EXTERNAL",
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))
    return key_id


def _safe_schedule_delete(client, key_id):
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
