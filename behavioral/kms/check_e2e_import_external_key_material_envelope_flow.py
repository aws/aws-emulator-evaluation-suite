"""e2e-import-external-key-material-envelope-flow."""
from __future__ import annotations

import os
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-import-external-key-material-envelope-flow"
GROUP = "state-machine"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Import external key material, use it for a real Encrypt/Decrypt round trip,
    delete the imported material, and confirm the key becomes unusable for Decrypt
    (KMSInvalidStateException) until the same material is re-imported."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    key_resp = kms.create_key(
        Origin="EXTERNAL",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-import-envelope-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-envelope-flow"}],
    )
    key_id = key_resp["KeyMetadata"]["KeyId"]
    assert key_resp["KeyMetadata"]["KeyState"] == "PendingImport", (
        f"expected PendingImport right after create_key(Origin=EXTERNAL), "
        f"got {key_resp['KeyMetadata']['KeyState']!r}"
    )
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    key_material = os.urandom(32)  # 256-bit AES material for SYMMETRIC_DEFAULT

    def _wrap(public_key_der: bytes) -> bytes:
        pub = serialization.load_der_public_key(public_key_der)
        return pub.encrypt(
            key_material,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    params = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    wrapped = _wrap(params["PublicKey"])
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    desc = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["KeyState"] == "Enabled",
        timeout_s=60.0,
        what=f"{key_id} to reach Enabled after ImportKeyMaterial",
    )
    assert desc["KeyState"] == "Enabled", desc["KeyState"]

    plaintext = b"sim2real-import-key-material-payload"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    # Positive control BEFORE breaking anything: the freshly imported key works.
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"expected {plaintext!r}, got {decrypted!r}"

    # Break exactly one thing: delete the imported key material.
    kms.delete_imported_key_material(KeyId=key_id)
    desc_after_delete = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["KeyState"] == "PendingImport",
        timeout_s=60.0,
        what=f"{key_id} to revert to PendingImport after DeleteImportedKeyMaterial",
    )
    assert desc_after_delete["KeyState"] == "PendingImport", desc_after_delete["KeyState"]

    # describe_key already settled at PendingImport above, so Decrypt is deterministically
    # refused now — no separate retry needed for the data-plane call.
    error_code, error_message = _error(lambda: kms.decrypt(CiphertextBlob=ciphertext))
    assert error_code == "KMSInvalidStateException", (
        f"expected KMSInvalidStateException, got {error_code!r}"
    )
    assert error_message == f"{key_resp['KeyMetadata']['Arn']} is pending import.", f"unexpected message {error_message!r}"

    # Re-import the SAME raw key material -> the OLD ciphertext must decrypt again,
    # proving the key material (not just "some" material) is what was restored.
    params2 = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    wrapped2 = _wrap(params2["PublicKey"])
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params2["ImportToken"],
        EncryptedKeyMaterial=wrapped2,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )

    desc_after_reimport = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["KeyState"] == "Enabled",
        timeout_s=60.0,
        what=f"{key_id} to reach Enabled after re-ImportKeyMaterial",
    )
    assert desc_after_reimport["KeyState"] == "Enabled", desc_after_reimport["KeyState"]
    restored = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert restored == plaintext, (
        f"re-importing the identical material must reopen the pre-delete ciphertext: "
        f"expected {plaintext!r}, got {restored!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError.

    Raises on unexpected success rather than returning a falsy sentinel.
    """
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("the call was expected to fail and it succeeded")


def _poll_until(
    probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float,
    interval_s: float = 2.0, what: str = "",
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
