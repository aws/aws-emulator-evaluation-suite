"""op-cancel-deletion-when-not-pending-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-cancel-deletion-when-not-pending-rejected"
GROUP = 'key_lifecycle'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelKeyDeletion is only valid from PendingDeletion; Enabled/Disabled keys are rejected
    without the key state advancing, and the identical call succeeds once the key actually is
    PendingDeletion."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("kms-op-cancel-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-op-cancel-deletion-when-not-pending-rejected"}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    not_pending = f"{meta['Arn']} is not pending deletion."
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    code, message = _error(lambda: kms.cancel_key_deletion(KeyId=key_id))
    assert code == "KMSInvalidStateException", f"expected KMSInvalidStateException on Enabled, got {code}"
    assert message == not_pending, f"Enabled -> unexpected message {message!r}"
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"rejected CancelKeyDeletion must not change key state, got {state}"

    kms.disable_key(KeyId=key_id)
    code2, message2 = _error(lambda: kms.cancel_key_deletion(KeyId=key_id))
    assert code2 == "KMSInvalidStateException", f"expected KMSInvalidStateException on Disabled, got {code2}"
    assert message2 == not_pending, f"Disabled -> unexpected message {message2!r}"
    state2 = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state2 == "Disabled", f"rejected CancelKeyDeletion must not change key state, got {state2}"

    # Positive control: the identical call succeeds once the key is genuinely PendingDeletion,
    # proving the two rejections above are a state guard and not a target that refuses every call.
    kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    scheduled_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert scheduled_state == "PendingDeletion", f"expected PendingDeletion, got {scheduled_state}"

    kms.cancel_key_deletion(KeyId=key_id)
    restored_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert restored_state == "Disabled", f"CancelKeyDeletion must restore Disabled, got {restored_state}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
