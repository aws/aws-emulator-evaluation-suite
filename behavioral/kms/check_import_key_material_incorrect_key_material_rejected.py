"""import-key-material-incorrect-key-material-rejected."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-key-material-incorrect-key-material-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After material A is imported and then deleted (key PendingImport), importing different material B fails
    with IncorrectKeyMaterialException and the exact message and the key stays PendingImport, while
    re-importing A under a fresh token makes the key Enabled."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    created = kms.create_key(
        Origin="EXTERNAL",
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-key-material-incorrect-key-material-rejected"}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _best_effort_schedule_deletion(kms, key_id))

    def _get_wrapper():
        params = kms.get_parameters_for_import(
            KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
        )
        return params, serialization.load_der_public_key(params["PublicKey"])

    def _wrap(public_key, material: bytes) -> bytes:
        return public_key.encrypt(
            material,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )

    material_a = os.urandom(32)  # SYMMETRIC_DEFAULT (AES-256) requires exactly 32 bytes

    # first import of material A succeeds and enables the key
    params, public_key = _get_wrapper()
    first_import = kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=_wrap(public_key, material_a),
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    enabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        interval_s=2,
    )
    assert enabled["KeyState"] == "Enabled", f"expected Enabled after importing material A, got {enabled['KeyState']!r}"

    # remove it, returning the key to PendingImport, without changing the key's identity
    kms.delete_imported_key_material(KeyId=key_id)
    pending = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "PendingImport",
        timeout_s=60,
        interval_s=2,
    )
    assert pending["KeyState"] == "PendingImport", f"expected PendingImport after deleting imported material, got {pending['KeyState']!r}"

    # break exactly one thing: attempt to import DIFFERENT material B with a fresh token
    material_b = os.urandom(32)
    params_b, public_key_b = _get_wrapper()
    code, message = _error(
        lambda: kms.import_key_material(
            KeyId=key_id,
            ImportToken=params_b["ImportToken"],
            EncryptedKeyMaterial=_wrap(public_key_b, material_b),
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )
    )
    assert code == "IncorrectKeyMaterialException", f"expected IncorrectKeyMaterialException rejecting mismatched material, got {code!r}"
    expected_message = (
        "Imported key material does not have the expected identifier "
        f"({first_import['KeyMaterialId']})."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # effect-absent: the key stayed in PendingImport, the rejected import had no effect
    still_pending = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert still_pending["KeyState"] == "PendingImport", (
        f"a rejected import must not change the key's state, got {still_pending['KeyState']!r}"
    )

    # positive control: reimporting the ORIGINAL material A (fresh token) succeeds
    params_c, public_key_c = _get_wrapper()
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params_c["ImportToken"],
        EncryptedKeyMaterial=_wrap(public_key_c, material_a),
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    re_enabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        interval_s=2,
    )
    assert re_enabled["KeyState"] == "Enabled", (
        f"reimporting the original material must restore Enabled, got {re_enabled['KeyState']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _best_effort_schedule_deletion(kms, key_id):
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

