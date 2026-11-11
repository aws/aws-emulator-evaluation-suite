"""error-disabled-key-encrypt."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-disabled-key-encrypt"
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt on a disabled key raises DisabledException; re-enabling restores it."""
    kms = ctx.client("kms")
    key_meta = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-error-disabled-key-encrypt"}],
    )["KeyMetadata"]
    key_id = key_meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    plaintext = b"test"
    # positive control: the fresh, enabled key encrypts and decrypts normally
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"Expected round-trip {plaintext!r}, got {decrypted!r}"

    kms.disable_key(KeyId=key_id)
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"Expected KeyState Disabled after DisableKey, got {state!r}"

    code, message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=plaintext))
    assert code == ERR_DISABLED, f"Expected {ERR_DISABLED}, got {code!r}"
    assert message == f"{key_meta['Arn']} is disabled.", f"unexpected message {message!r}"

    # effect absent: the key is still disabled, no encrypt succeeded while broken
    state_after = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state_after == "Disabled", f"Expected KeyState still Disabled, got {state_after!r}"

    # restore: re-enabling the identical key makes the identical call succeed again
    kms.enable_key(KeyId=key_id)
    restored_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert restored_state == "Enabled", f"Expected KeyState Enabled after EnableKey, got {restored_state!r}"
    ciphertext2 = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted2 = kms.decrypt(CiphertextBlob=ciphertext2)["Plaintext"]
    assert decrypted2 == plaintext, f"Expected round-trip after re-enable {plaintext!r}, got {decrypted2!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
