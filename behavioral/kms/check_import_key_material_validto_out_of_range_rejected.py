"""import-key-material-validto-out-of-range-rejected."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-key-material-validto-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportKeyMaterial rejects a ValidTo timestamp that is already in the past."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    key_id = _create_external_key(ctx)

    params = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm="RSAES_OAEP_SHA_256",
        WrappingKeySpec="RSA_2048",
    )
    import_token = params["ImportToken"]
    public_key = serialization.load_der_public_key(params["PublicKey"])
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )
    material = os.urandom(32)
    wrapped = public_key.encrypt(material, oaep)

    past = datetime.now(timezone.utc) - timedelta(days=1)
    code, message = _error(
        lambda: kms.import_key_material(
            KeyId=key_id,
            ImportToken=import_token,
            EncryptedKeyMaterial=wrapped,
            ExpirationModel="KEY_MATERIAL_EXPIRES",
            ValidTo=past,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "ValidTo must be in the future", message

    state_after_failure = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after_failure == "PendingImport", "a rejected import must not change the key's state"

    # positive control: the identical (token, wrapped material) pair with a future
    # ValidTo succeeds -- isolating the failure above to the ValidTo value itself
    future = datetime.now(timezone.utc) + timedelta(days=30)
    kms.import_key_material(
        KeyId=key_id,
        ImportToken=import_token,
        EncryptedKeyMaterial=wrapped,
        ExpirationModel="KEY_MATERIAL_EXPIRES",
        ValidTo=future,
    )
    state_after_success = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after_success == "Enabled", (
        f"expected the identical import with a future ValidTo to succeed, got {state_after_success}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target that accepts a past ValidTo must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_external_key(ctx):
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-ext-"),
        Origin="EXTERNAL",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
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
