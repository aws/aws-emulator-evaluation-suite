"""error-pending-deletion-encrypt."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-pending-deletion-encrypt"
GROUP = 'errors'
SERVICES = ['kms']

ERR_KMS_INVALID_STATE = "KMSInvalidStateException"

def _client_error(fn):
    """Call fn(); return the botocore Error it raises.

    An unexpected SUCCESS raises rather than returning a falsy sentinel: a target that
    accepts a call real AWS refuses is the strongest signal available and must not be
    reported as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt on a PendingDeletion key raises KMSInvalidStateException, and the refusal
    is reversible: CancelKeyDeletion + EnableKey restores the identical Encrypt call."""
    kms = ctx.client("kms")
    meta = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]
    key_id = meta["KeyId"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    # --- Positive control: Encrypt succeeds while the key is Enabled.
    # Encrypt echoes the key ARN in KeyId, not the raw id.
    control = kms.encrypt(KeyId=key_id, Plaintext=b"test")
    assert control["KeyId"] == key_arn, control["KeyId"]
    assert control["CiphertextBlob"], "positive control: Encrypt must return ciphertext"

    # --- Break exactly one thing: schedule the key for deletion.
    kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)

    # --- Effect present, via an independent read (DescribeKey, not Encrypt).
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyState"] == "PendingDeletion", described["KeyState"]

    # --- The specific refusal.
    err = _client_error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"test"))
    assert err["Code"] == ERR_KMS_INVALID_STATE, f"Expected {ERR_KMS_INVALID_STATE}, got {err!r}"
    expected = f"{key_arn} is pending deletion."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # --- Restore. CancelKeyDeletion lands on Disabled, not Enabled, so EnableKey follows.
    kms.cancel_key_deletion(KeyId=key_id)
    kms.enable_key(KeyId=key_id)
    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyState"] == "Enabled", described["KeyState"]

    # --- The identical call now succeeds again.
    restored = kms.encrypt(KeyId=key_id, Plaintext=b"test")
    assert restored["KeyId"] == key_arn, restored["KeyId"]
    assert restored["CiphertextBlob"], "after restore, Encrypt must return ciphertext again"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
