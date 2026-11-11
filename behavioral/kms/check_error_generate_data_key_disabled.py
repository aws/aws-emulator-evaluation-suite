"""error-generate-data-key-disabled."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-generate-data-key-disabled"
GROUP = 'errors'
SERVICES = ['kms']

ERR_DISABLED = "DisabledException"

def _error(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError; an
    unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateDataKey on a disabled key raises DisabledException, the key stays
    Disabled (no data key was generated), and the identical call succeeds again
    once the key is re-enabled."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "simparity-check", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    kms.disable_key(KeyId=key_id)
    desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert desc["Enabled"] is False, f"Expected Enabled False after DisableKey, got {desc['Enabled']!r}"
    assert desc["KeyState"] == "Disabled", f"Expected KeyState Disabled, got {desc['KeyState']!r}"

    code, message = _error(lambda: kms.generate_data_key(KeyId=key_id, KeySpec="AES_256"))
    assert code == ERR_DISABLED, f"Expected {ERR_DISABLED}, got {code!r}"
    assert message == f"{desc['Arn']} is disabled.", f"unexpected message {message!r}"

    # Effect absent: the key remains disabled after the rejected call.
    desc_after = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert desc_after["Enabled"] is False, f"Expected key to stay disabled, got {desc_after['KeyState']!r}"

    # Restore, and the identical call now succeeds.
    kms.enable_key(KeyId=key_id)
    desc_enabled = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert desc_enabled["Enabled"] is True, f"Expected key to be enabled, got {desc_enabled['KeyState']!r}"

    result = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    assert result["KeyId"] == desc_enabled["Arn"], f"Expected KeyId {desc_enabled['Arn']!r}, got {result['KeyId']!r}"
    assert len(result["Plaintext"]) == 32, f"Expected 32-byte AES_256 plaintext, got {len(result['Plaintext'])}"
    assert result["CiphertextBlob"], "Expected a non-empty CiphertextBlob once re-enabled"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
