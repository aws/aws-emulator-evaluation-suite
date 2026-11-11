"""imported-key-material-expiration-reverts-key-state."""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "imported-key-material-expiration-reverts-key-state"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kms"]


# timing:real-time — ttl: 8 s https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html
@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """Imported key material with a near-future ValidTo expires: KeyState reverts Enabled ->
    PendingImport and Encrypt fails; reimporting the same material re-enables the key.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    from botocore.exceptions import ClientError

    kms = ctx.client("kms")
    created = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Description=ctx.unique_name("sim2real-kms-import-ttl-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    key_arn = created["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    public_key = serialization.load_der_public_key(params["PublicKey"])
    key_material = os.urandom(32)  # SYMMETRIC_DEFAULT requires exactly 32 bytes
    wrapped = public_key.encrypt(
        key_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )

    # ValidTo only has to be in the future (ImportKeyMaterial, ValidTo), so 8 s keeps the wait short.
    valid_to = datetime.now(timezone.utc) + timedelta(seconds=8)
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_EXPIRES",
        ValidTo=valid_to,
    )

    state_after_import = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after_import == "Enabled", f"expected Enabled after import, got {state_after_import}"
    kms.encrypt(KeyId=key_id, Plaintext=b"pre-expiry-plaintext")

    # Expiry is enforced by a sweep that is not instantaneous, so poll well past ValidTo.
    deadline = time.monotonic() + _budget_s(ctx, 8 + 170)
    final_state = state_after_import
    while time.monotonic() < deadline:
        final_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if final_state == "PendingImport":
            break
        time.sleep(1)
    if final_state != "PendingImport" and _budget_spent(ctx):
        raise TimeoutError("key material to expire to PendingImport: the run budget ended first; not graded")
    assert final_state == "PendingImport", (
        f"key material never expired: KeyState stayed {final_state!r} well past ValidTo"
    )

    def _encrypt_after_expiry():
        kms.encrypt(KeyId=key_id, Plaintext=b"post-expiry-plaintext")

    try:
        _encrypt_after_expiry()
        raise AssertionError("Encrypt succeeded on a key whose imported material expired")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "KMSInvalidStateException", (
            f"expected KMSInvalidStateException for Encrypt on expired-material key, got {code!r}"
        )
        message = err.response["Error"].get("Message", "")
        assert message == f"{key_arn} is pending import.", message

    # A reimport must supply the original material; fresh random bytes are rejected with
    # IncorrectKeyMaterialException.
    restore_params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    restore_public_key = serialization.load_der_public_key(restore_params["PublicKey"])
    restore_wrapped = restore_public_key.encrypt(
        key_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=restore_params["ImportToken"],
        EncryptedKeyMaterial=restore_wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    restore_deadline = time.monotonic() + _budget_s(ctx, 30)
    restored_state = None
    while time.monotonic() < restore_deadline:
        restored_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if restored_state == "Enabled":
            break
        time.sleep(1)
    if restored_state != "Enabled" and _budget_spent(ctx):
        raise TimeoutError("key to return to Enabled after reimport: the run budget ended first; not graded")
    assert restored_state == "Enabled", (
        f"key never returned to Enabled after reimporting fresh key material, stayed "
        f"{restored_state!r}"
    )
    kms.encrypt(KeyId=key_id, Plaintext=b"post-restore-plaintext")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
