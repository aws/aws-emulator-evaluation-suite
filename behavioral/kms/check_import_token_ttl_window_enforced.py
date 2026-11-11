"""import-token-ttl-window-enforced."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "import-token-ttl-window-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ParametersValidTo is ~24h out, and an ImportToken is bound to its KeyId: using it for a
    different EXTERNAL key fails with InvalidImportTokenException; the matched key imports.

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_GetParametersForImport.html
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")

    key_a = kms.create_key(
        Origin="EXTERNAL",
        Description=ctx.unique_name("sim2real-kms-imp-a-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-token-ttl-window-enforced"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_a, PendingWindowInDays=7))
    key_b = kms.create_key(
        Origin="EXTERNAL",
        Description=ctx.unique_name("sim2real-kms-imp-b-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-import-token-ttl-window-enforced"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_b, PendingWindowInDays=7))

    params_a = kms.get_parameters_for_import(
        KeyId=key_a, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
    )

    # The window is fixed at 24h and cannot be shortened, so expiry itself is not waited out;
    # +/- 30 min tolerates round-trip and clock skew.
    now = datetime.now(timezone.utc)
    valid_to = params_a["ParametersValidTo"]
    delta = valid_to - now
    assert timedelta(hours=23, minutes=30) <= delta <= timedelta(hours=24, minutes=30), (
        f"expected ParametersValidTo ~24h from now, got delta={delta}"
    )

    key_material_a = os.urandom(32)
    public_key_a = serialization.load_der_public_key(params_a["PublicKey"])
    wrapped_a = public_key_a.encrypt(
        key_material_a,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )

    # Break exactly one thing: present key A's import token while targeting key B.
    code, message = _error(
        lambda: kms.import_key_material(
            KeyId=key_b,
            ImportToken=params_a["ImportToken"],
            EncryptedKeyMaterial=wrapped_a,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )
    )
    assert code == "InvalidImportTokenException", f"expected InvalidImportTokenException, got {code}"
    assert message == "", f"expected an empty InvalidImportTokenException message, got {message!r}"

    # Effect absent: key B never received material and stays PendingImport.
    state_b = kms.describe_key(KeyId=key_b)["KeyMetadata"]["KeyState"]
    assert state_b == "PendingImport", f"expected key B to remain PendingImport, got {state_b}"

    # The matched token/key pair imports successfully.
    from botocore.exceptions import ClientError

    try:
        kms.import_key_material(
            KeyId=key_a,
            ImportToken=params_a["ImportToken"],
            EncryptedKeyMaterial=wrapped_a,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )
    except ClientError as err:
        raise AssertionError(
            "expected the matched token/key import to succeed, got "
            f"{err.response['Error']['Code']}"
        ) from err
    state_a = kms.describe_key(KeyId=key_a)["KeyMetadata"]["KeyState"]
    assert state_a == "Enabled", f"expected key A to become Enabled, got {state_a}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
