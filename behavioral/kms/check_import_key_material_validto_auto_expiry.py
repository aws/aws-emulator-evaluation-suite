"""import-key-material-validto-auto-expiry."""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "import-key-material-validto-auto-expiry"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kms"]


# timing:real-time — ttl: 8 s https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Material imported with KEY_MATERIAL_EXPIRES and a near-future ValidTo is deleted by KMS:
    the key reverts to PendingImport and Encrypt fails, with no DeleteImportedKeyMaterial call.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-import-key-material.html
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    created = kms.create_key(
        Origin="EXTERNAL",
        Description=ctx.unique_name("sim2real-kms-expiry-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-key-material-validto-auto-expiry"}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    key_arn = created["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    state0 = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state0 == "PendingImport", f"expected new EXTERNAL key to start PendingImport, got {state0}"

    params = kms.get_parameters_for_import(
        KeyId=key_id, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )
    key_material = os.urandom(32)  # exactly 32 bytes for a SYMMETRIC_DEFAULT (AES-256) key
    public_key = serialization.load_der_public_key(params["PublicKey"])
    wrapped = public_key.encrypt(
        key_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )

    # ValidTo has no minimum beyond being in the future, so seconds out is legal.
    valid_to = datetime.now(timezone.utc) + timedelta(seconds=8)
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_EXPIRES",
        ValidTo=valid_to,
    )

    state1 = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "Enabled",
        timeout_s=10.0,
        interval_s=1.0,
    )
    assert state1 == "Enabled", f"expected key to become Enabled after import, got {state1}"

    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=b"validto-probe")["CiphertextBlob"]
    assert ciphertext, "expected Encrypt to succeed on freshly imported key material"

    # Deletion of expired material has no documented promptness, so poll with a bound
    # instead of asserting at the ValidTo boundary.
    final_state = _poll_until(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"],
        lambda s: s == "PendingImport",
        timeout_s=_budget_s(ctx, 480.0),
        interval_s=1.0,
    )
    if final_state != "PendingImport" and _budget_spent(ctx):
        raise TimeoutError("imported key material to auto-expire to PendingImport: the run budget ended first; not graded")
    assert final_state == "PendingImport", (
        "expected imported key material to auto-expire back to PendingImport by/after "
        f"its ValidTo, got {final_state}"
    )

    code, message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"post-expiry-probe"))
    assert code == "KMSInvalidStateException", f"expected KMSInvalidStateException after auto-expiry, got {code}"
    assert message == f"{key_arn} is pending import.", message


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected Encrypt to fail with KMSInvalidStateException after auto-expiry, "
        f"but it SUCCEEDED and returned {result!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
