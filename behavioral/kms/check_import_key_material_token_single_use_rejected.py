"""import-key-material-token-single-use-rejected."""
from __future__ import annotations

import os
import time

from behavioral_harness import tags

CHECK = "import-key-material-token-single-use-rejected"
GROUP = "concurrency"
SERVICES = ["kms"]


def _wrap(public_key_der: bytes, material: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    public_key = serialization.load_der_public_key(public_key_der)
    return public_key.encrypt(
        material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _outcome(fn):
    """(error, None) when fn() is refused, (None, response) when it succeeds."""
    from botocore.exceptions import ClientError

    try:
        return None, fn()
    except ClientError as err:
        return err.response["Error"], None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing one (token, wrapped material) pair for two NEW_KEY_MATERIAL imports yields one
    success and one IncorrectKeyMaterialException with a single PENDING_ROTATION material; a
    fresh reimport still succeeds and the key round-trips data."""
    import cryptography  # noqa: F401

    kms = ctx.client("kms")

    key_meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kmsimport-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Origin="EXTERNAL",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key_meta["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    params0 = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    material0 = os.urandom(32)
    encrypted0 = _wrap(params0["PublicKey"], material0)
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params0["ImportToken"],
        EncryptedKeyMaterial=encrypted0,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    key_state = None
    for _ in range(20):
        key_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if key_state == "Enabled":
            break
        time.sleep(0.5)
    assert key_state == "Enabled", f"key never reached Enabled after initial import: {key_state}"

    params1 = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    material1 = os.urandom(32)
    encrypted1 = _wrap(params1["PublicKey"], material1)

    def _import_new():
        return kms.import_key_material(
            KeyId=key_id,
            ImportToken=params1["ImportToken"],
            EncryptedKeyMaterial=encrypted1,
            ImportType="NEW_KEY_MATERIAL",
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )

    # Sequential, so the reuse is refused deterministically (a true race has no documented
    # outcome).
    err_a, ok_a = _outcome(_import_new)
    err_b, ok_b = _outcome(_import_new)

    outcomes = [(err_a, ok_a), (err_b, ok_b)]
    successes = [ok for err, ok in outcomes if err is None]
    failures = [err for err, ok in outcomes if err is not None]

    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)}: {outcomes}"
    assert len(failures) == 1, f"expected exactly 1 failure, got {len(failures)}: {outcomes}"
    assert failures[0]["Code"] == "IncorrectKeyMaterialException", (
        f"expected IncorrectKeyMaterialException for the reused token, got {failures[0]!r}"
    )

    rotations = kms.list_key_rotations(KeyId=key_id, IncludeKeyMaterial="ALL_KEY_MATERIAL")[
        "Rotations"
    ]
    pending = [r for r in rotations if r["KeyMaterialState"] == "PENDING_ROTATION"]
    assert len(pending) == 1, (
        f"expected exactly 1 PENDING_ROTATION key material after the race, got {len(pending)}: "
        f"{rotations}"
    )
    assert len(rotations) == 2, f"expected exactly 2 key materials total, got {rotations}"
    expected = (
        f"Key material (id: {pending[0]['KeyMaterialId']}) being imported as NEW_KEY_MATERIAL "
        f"is already associated with KMS key {key_meta['Arn']}."
    )
    assert failures[0]["Message"] == expected, (
        f"expected message {expected!r}, got {failures[0]['Message']!r}"
    )

    params2 = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    encrypted0_again = _wrap(params2["PublicKey"], material0)
    control_resp = kms.import_key_material(
        KeyId=key_id,
        ImportToken=params2["ImportToken"],
        EncryptedKeyMaterial=encrypted0_again,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    assert "KeyMaterialId" in control_resp, (
        f"expected the legitimate reimport to return a KeyMaterialId, got {control_resp!r}"
    )

    probe_plaintext = b"import-key-material-single-use-rejected-probe"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=probe_plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == probe_plaintext, (
        f"key was not genuinely usable after the legitimate reimport: roundtrip mismatch "
        f"(got {decrypted!r}, expected {probe_plaintext!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
