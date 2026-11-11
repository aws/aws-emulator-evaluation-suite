"""import-key-material-tampered-blob-rejected."""
from __future__ import annotations

import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-key-material-tampered-blob-rejected"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportKeyMaterial with one bit flipped in the RSA-OAEP wrapped material fails with InvalidCiphertextException
    and an empty message, leaving the key PendingImport, while the correctly wrapped blob imports and the key
    becomes Enabled."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-tamperimport-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Origin="EXTERNAL",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    params = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    public_key = load_der_public_key(params["PublicKey"])
    key_material = os.urandom(32)
    wrapped = public_key.encrypt(
        key_material,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    tampered = bytearray(wrapped)
    tampered[-1] ^= 0xFF
    tampered_blob = bytes(tampered)

    code, message = _error(
        lambda: kms.import_key_material(
            KeyId=key_id,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=tampered_blob,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )
    )
    assert code == "InvalidCiphertextException", (
        f"a single flipped bit in the OAEP-wrapped key material must be rejected as "
        f"InvalidCiphertextException, got {code!r}"
    )
    assert message == "", f"expected an empty InvalidCiphertextException message, got {message!r}"

    state_after_failure = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after_failure == "PendingImport", (
        f"tampered import must not install any key material, got KeyState={state_after_failure}"
    )

    # Positive control: fresh import parameters + correctly wrapped material for the same key
    # succeed, proving the rejection above was specific to the tampering.
    params2 = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    public_key2 = load_der_public_key(params2["PublicKey"])
    good_wrapped = public_key2.encrypt(
        key_material,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params2["ImportToken"],
        EncryptedKeyMaterial=good_wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    state_after_success = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after_success == "Enabled", (
        f"a correctly wrapped import of the same key material for the same key must "
        f"succeed, got KeyState={state_after_success}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target that accepts a tampered blob must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
