"""import-key-material-state-transitions."""
from __future__ import annotations

import os
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-key-material-state-transitions"
GROUP = "state-machine"
SERVICES = ["kms"]

ERR_INVALID_STATE = "KMSInvalidStateException"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A KMS_EXTERNAL key cycles PendingImport -> Enabled -> PendingImport as key material is
    imported and then explicitly deleted. At each end of the cycle the state label is corroborated
    by whether the key can actually be used for Encrypt, not just by describe_key's own report."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    key = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-key-material-state-transitions"}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    pending_import = f"{key['KeyMetadata']['Arn']} is pending import."
    ctx.on_cleanup(lambda: _best_effort(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)))
    assert key["KeyMetadata"]["KeyState"] == "PendingImport", (
        f"a freshly created Origin=EXTERNAL key must start PendingImport, got "
        f"{key['KeyMetadata']['KeyState']!r}"
    )

    # Before material exists, the key must be unusable — not merely labelled PendingImport.
    pre_import = _client_error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"probe"))
    assert pre_import["Code"] == ERR_INVALID_STATE, (
        f"Encrypt with no key material imported must raise {ERR_INVALID_STATE}, got {pre_import!r}"
    )
    assert pre_import["Message"] == pending_import, (
        f"expected message {pending_import!r}, got {pre_import['Message']!r}"
    )

    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    public_key = serialization.load_der_public_key(params["PublicKey"])
    key_material = os.urandom(32)  # AES-256, matches SYMMETRIC_DEFAULT
    wrapped = public_key.encrypt(
        key_material,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    state = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s != "PendingImport",
        timeout_s=30,
    )
    assert state == "Enabled", f"expected Enabled after import, got {state}"

    # Prove the imported material is genuinely usable, not just a state-label flip.
    plaintext = b"sim2real-import-key-material-state-transitions"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id)["Plaintext"]
    assert decrypted == plaintext, (
        f"round-trip through the imported material must return the original plaintext, got "
        f"{decrypted!r} for {plaintext!r}"
    )

    kms.delete_imported_key_material(KeyId=key_id)
    state = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "PendingImport",
        timeout_s=30,
    )
    assert state == "PendingImport", f"expected PendingImport after deleting imported material, got {state}"

    # The reverted label must be backed by an actual loss of usability: the mutation that worked
    # moments ago (Encrypt, above) must now fail with the specific no-material error.
    post_delete = _client_error(lambda: kms.encrypt(KeyId=key_id, Plaintext=plaintext))
    assert post_delete["Code"] == ERR_INVALID_STATE, (
        f"Encrypt after DeleteImportedKeyMaterial must raise {ERR_INVALID_STATE}, got {post_delete!r}"
    )
    assert post_delete["Message"] == pending_import, (
        f"expected message {pending_import!r}, got {post_delete['Message']!r}"
    )


def _client_error(fn):
    """Return the botocore Error if fn() raises ClientError.

    An unexpected SUCCESS raises rather than returning a falsy sentinel: a target that accepts a
    call real AWS refuses is the strongest signal available and must not read as a code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call was expected to fail and it succeeded")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
