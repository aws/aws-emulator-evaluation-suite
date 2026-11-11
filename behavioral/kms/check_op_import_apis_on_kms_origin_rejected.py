"""op-import-apis-on-kms-origin-rejected."""
from __future__ import annotations

import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-import-apis-on-kms-origin-rejected"
GROUP = 'key_lifecycle'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetParametersForImport and DeleteImportedKeyMaterial on an AWS_KMS-origin key fail with
    UnsupportedOperationException and leave it usable; both succeed on an EXTERNAL-origin key."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("kms-op-import-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    assert meta["Origin"] == "AWS_KMS", meta["Origin"]

    wrong_origin = f"{meta['Arn']} origin is AWS_KMS which is not valid for this operation."
    code, message = _error(
        lambda: kms.get_parameters_for_import(
            KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
        )
    )
    assert code == "UnsupportedOperationException", f"GetParametersForImport -> got {code}"
    assert message == wrong_origin, f"GetParametersForImport -> {message!r}"

    code2, message2 = _error(lambda: kms.delete_imported_key_material(KeyId=key_id))
    assert code2 == "UnsupportedOperationException", f"DeleteImportedKeyMaterial -> got {code2}"
    assert message2 == wrong_origin, f"DeleteImportedKeyMaterial -> {message2!r}"

    after_reject = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert after_reject["Origin"] == "AWS_KMS", after_reject["Origin"]
    assert after_reject["KeyState"] == "Enabled", after_reject["KeyState"]
    plaintext = b"sim2real-kms-op-import-native-still-usable"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    assert kms.decrypt(KeyId=key_id, CiphertextBlob=ciphertext)["Plaintext"] == plaintext

    ext_meta = kms.create_key(
        Origin="EXTERNAL",
        Description=ctx.unique_name("kms-op-import-external-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ext_key_id = ext_meta["KeyId"]
    ctx.on_cleanup(lambda _k=ext_key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    params = kms.get_parameters_for_import(
        KeyId=ext_key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    assert len(params["PublicKey"]) > 0
    assert len(params["ImportToken"]) > 0

    key_material = os.urandom(32)
    public_key = serialization.load_der_public_key(params["PublicKey"])
    wrapped = public_key.encrypt(
        key_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    kms.import_key_material(
        KeyId=ext_key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    _poll_until(
        lambda: kms.describe_key(KeyId=ext_key_id)["KeyMetadata"],
        lambda d: d["KeyState"] != "PendingImport",
        timeout_s=60.0,
    )

    kms.delete_imported_key_material(KeyId=ext_key_id)
    reverted = _poll_until(
        lambda: kms.describe_key(KeyId=ext_key_id)["KeyMetadata"],
        lambda d: d["KeyState"] == "PendingImport",
        timeout_s=60.0,
    )
    assert reverted["KeyState"] == "PendingImport", reverted["KeyState"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
