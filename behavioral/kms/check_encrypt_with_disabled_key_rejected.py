"""encrypt-with-disabled-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "encrypt-with-disabled-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt against a DISABLED KMS key is rejected with DisabledException, no
    ciphertext is produced, and the same key works again once re-enabled."""
    kms = ctx.client("kms")
    key_resp = kms.create_key(
        Description="sim2real disabled-key-rejected test key",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "encrypt-with-disabled-key-rejected"}],
    )
    key_id = key_resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    kms.disable_key(KeyId=key_id)
    desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert desc["Enabled"] is False, f"expected Enabled=False after DisableKey, got {desc['Enabled']!r}"
    assert desc["KeyState"] == "Disabled", f"expected KeyState=Disabled, got {desc['KeyState']!r}"

    error_code, error_message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"should-not-encrypt"))
    assert error_code == "DisabledException", f"expected DisabledException, got {error_code!r}"
    assert error_message == f"{key_resp['KeyMetadata']['Arn']} is disabled.", f"unexpected message {error_message!r}"

    # Effect absent: the key is still disabled, no encrypt operation succeeded.
    desc_after = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert desc_after["Enabled"] is False, (
        f"expected Enabled=False to persist after the rejected Encrypt, got {desc_after['Enabled']!r}"
    )

    # Positive control in the same file: re-enable and the same key now works.
    kms.enable_key(KeyId=key_id)
    desc_enabled = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert desc_enabled["Enabled"] is True, f"expected Enabled=True after EnableKey, got {desc_enabled['Enabled']!r}"

    plaintext = b"sim2real-reenabled-key-payload"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"expected re-enabled key to decrypt to {plaintext!r}, got {decrypted!r}"


def _error(fn):
    """Return the botocore (Error.Code, Error.Message) of the refused call; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
