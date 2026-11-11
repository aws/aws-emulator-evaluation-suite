"""error-disabled-key-decrypt."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-disabled-key-decrypt"
GROUP = 'errors'
SERVICES = ['kms']

ERR_DISABLED = "DisabledException"

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects Decrypt on a Disabled key, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Decrypt on a disabled key raises DisabledException while the key is Disabled, and the
    identical Decrypt call succeeds again once EnableKey restores it."""
    kms = ctx.client("kms")
    key_meta = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]
    key_id = key_meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    plaintext = b"test-disabled-decrypt"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]

    # Positive control: Decrypt works on this key while it is enabled.
    control = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert control == plaintext, f"expected pre-disable Decrypt to return {plaintext!r}, got {control!r}"

    kms.disable_key(KeyId=key_id)
    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyState"] == "Disabled", f"expected KeyState='Disabled' after DisableKey, got {meta['KeyState']!r}"

    decrypt_err = _client_error(lambda: kms.decrypt(CiphertextBlob=ciphertext))
    assert decrypt_err.get("Code") == ERR_DISABLED, (
        f"Decrypt on a Disabled key raised {decrypt_err.get('Code')!r}, expected {ERR_DISABLED!r}"
    )
    expected = f"{key_meta['Arn']} is disabled."
    assert decrypt_err.get("Message") == expected, (
        f"expected message {expected!r}, got {decrypt_err.get('Message')!r}"
    )

    kms.enable_key(KeyId=key_id)
    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyState"] == "Enabled", f"expected KeyState='Enabled' after EnableKey, got {meta['KeyState']!r}"

    restored = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert restored == plaintext, (
        f"Decrypt of the same ciphertext after EnableKey returned {restored!r}, expected {plaintext!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
