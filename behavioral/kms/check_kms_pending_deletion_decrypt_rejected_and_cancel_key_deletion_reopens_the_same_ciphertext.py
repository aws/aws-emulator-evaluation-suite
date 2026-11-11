"""kms-pending-deletion-decrypt-rejected-and-cancel-key-deletion-reopens-the-same-ciphertext."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "kms-pending-deletion-decrypt-rejected-and-cancel-key-deletion-reopens-the-same-ciphertext"
GROUP = 'key_lifecycle'
SERVICES = ['kms']

ERR_INVALID_STATE = "KMSInvalidStateException"
ERR_DISABLED = "DisabledException"


def _err_code(fn):
    """Return the botocore error response (Error + ResponseMetadata) if fn() raises ClientError.

    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError("the call was expected to fail and it succeeded")


def _assert_refusal(response, code: str, key_arn: str, what: str) -> tuple[str, str]:
    """Grade a refusal: the code, HTTP 400, and a message naming the key ARN. Returns the
    code and the message."""
    got = response.get("Error", {}).get("Code")
    assert got == code, f"{what} must raise {code}, got {got!r}"
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 400, f"{what} must carry HTTP 400, got {status!r}"
    message = response.get("Error", {}).get("Message") or ""
    assert key_arn in message, f"{what}: the message does not name {key_arn!r}: {message!r}"
    return got, message


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted, idempotently under either state."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return  # already PendingDeletion — the check may have left it there
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _poll_until(fn, predicate, *, timeout_s: float, interval_s: float = 2.0, what: str = ""):
    """Poll fn() until predicate(value) is true. Returns the value, or raises AssertionError."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last saw {last!r}")


def _list_key_ids(kms) -> set:
    """Every customer CMK id in the account, fully paginated."""
    ids = set()
    for page in kms.get_paginator("list_keys").paginate():
        ids.update(k["KeyId"] for k in page["Keys"])
    return ids


def _enabled_keys(kms, only: set) -> set:
    """The keys of `only` that ListKeys enumerates in state Enabled."""
    return {k for k in _list_key_ids(kms) & only
            if kms.describe_key(KeyId=k)["KeyMetadata"]["KeyState"] == "Enabled"}


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Decrypt under a PendingDeletion key fails with KMSInvalidStateException; CancelKeyDeletion
    lands on Disabled (DisabledException), and EnableKey reopens the original ciphertext.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-pendel-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-pending-deletion-excursion"}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    plaintext = b"must-survive-a-scheduled-deletion-and-a-cancel"
    enc_ctx = {"tenant": "acme", "purpose": "lifecycle"}

    # --- Pre-state baseline: the ciphertext opens while the key is Enabled.
    ct = kms.encrypt(
        KeyId=key_arn, Plaintext=plaintext, EncryptionContext=enc_ctx
    )["CiphertextBlob"]
    assert kms.decrypt(
        CiphertextBlob=ct, KeyId=key_arn, EncryptionContext=enc_ctx
    )["Plaintext"] == plaintext, (
        "pre-state baseline: the ciphertext must open before the deletion is scheduled"
    )

    # --- Break exactly one thing: schedule the key for deletion. Nothing else changes.
    scheduled = kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
    assert scheduled["KeyId"] == key_arn, scheduled["KeyId"]
    assert scheduled["PendingWindowInDays"] == 7, (
        f"ScheduleKeyDeletion must echo the window it applied as an integer, got "
        f"{scheduled['PendingWindowInDays']!r}"
    )
    assert scheduled["KeyState"] == "PendingDeletion", scheduled["KeyState"]
    assert isinstance(scheduled["DeletionDate"], datetime.datetime), (
        f"DeletionDate must be a timestamp, got {scheduled['DeletionDate']!r}"
    )

    # DescribeKey reports PendingDeletion slightly before it reports DeletionDate; wait for both.
    meta_pending = _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] == "PendingDeletion" and "DeletionDate" in m,
        timeout_s=120,
        what=f"{key_arn} to report PendingDeletion with a DeletionDate",
    )
    assert meta_pending["DeletionDate"] == scheduled["DeletionDate"], (
        f"DescribeKey must report the same DeletionDate ScheduleKeyDeletion returned: "
        f"{meta_pending['DeletionDate']!r} vs {scheduled['DeletionDate']!r}"
    )
    window = meta_pending["DeletionDate"] - meta_pending["CreationDate"]
    assert datetime.timedelta(days=6) < window < datetime.timedelta(days=8), (
        f"a 7-day pending window must put the DeletionDate ~7 days out, got {window!r}"
    )
    assert meta_pending["Enabled"] is False, meta_pending

    # --- The data plane is closed, with the state-specific code.
    pending_message = f"{key_arn} is pending deletion."
    code_dec, message_dec = _assert_refusal(
        _err_code(lambda: kms.decrypt(CiphertextBlob=ct, KeyId=key_arn, EncryptionContext=enc_ctx)),
        ERR_INVALID_STATE, key_arn, "Decrypt while PendingDeletion",
    )
    assert message_dec == pending_message, (
        f"Decrypt while PendingDeletion: expected message {pending_message!r}, got {message_dec!r}"
    )
    _, message_enc = _assert_refusal(
        _err_code(lambda: kms.encrypt(KeyId=key_arn, Plaintext=plaintext)),
        ERR_INVALID_STATE, key_arn, "Encrypt while PendingDeletion",
    )
    assert message_enc == pending_message, (
        f"Encrypt while PendingDeletion: expected message {pending_message!r}, got {message_enc!r}"
    )

    # --- Effect absent: the key record itself survives and is still enumerable. It is
    # scheduled, not gone.
    assert key_id in _list_key_ids(kms), (
        f"{key_id!r} vanished from ListKeys while merely PendingDeletion — the record must "
        f"survive the whole 7-day window"
    )

    # --- Positive control, part 1: the excursion is reversible. CancelKeyDeletion lands on
    # Disabled (NOT Enabled) and clears the DeletionDate.
    cancelled_resp = kms.cancel_key_deletion(KeyId=key_arn)
    assert cancelled_resp["KeyId"] == key_arn, cancelled_resp["KeyId"]
    meta_cancelled = _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] != "PendingDeletion",
        timeout_s=120,
        what=f"{key_arn} to leave PendingDeletion",
    )
    assert meta_cancelled["KeyState"] == "Disabled", (
        f"CancelKeyDeletion must land on Disabled, not straight back on Enabled, got "
        f"{meta_cancelled['KeyState']!r}"
    )
    assert "DeletionDate" not in meta_cancelled, (
        f"CancelKeyDeletion must clear the DeletionDate: {meta_cancelled!r}"
    )
    assert meta_cancelled["Enabled"] is False, meta_cancelled

    # --- Disabled and PendingDeletion are distinct states: Disabled refuses
    # the very same Decrypt with a DIFFERENT code than PendingDeletion did.
    code_disabled, message_disabled = _assert_refusal(
        _err_code(lambda: kms.decrypt(CiphertextBlob=ct, KeyId=key_arn, EncryptionContext=enc_ctx)),
        ERR_DISABLED, key_arn, "Decrypt on a Disabled key (not the PendingDeletion code)",
    )
    disabled_message = f"{key_arn} is disabled."
    assert message_disabled == disabled_message, (
        f"Decrypt on a Disabled key: expected message {disabled_message!r}, got {message_disabled!r}"
    )
    assert code_disabled != code_dec, (
        f"Disabled and PendingDeletion must be distinguishable on the data plane; both "
        f"returned {code_disabled!r}"
    )

    # --- Positive control, part 2: the ORIGINAL blob, minted before any of this, reopens.
    kms.enable_key(KeyId=key_arn)
    meta_enabled = _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] == "Enabled",
        timeout_s=60,
        what=f"{key_arn} to report Enabled",
    )
    assert meta_enabled["Enabled"] is True, meta_enabled
    assert "DeletionDate" not in meta_enabled, meta_enabled

    final = kms.decrypt(CiphertextBlob=ct, KeyId=key_arn, EncryptionContext=enc_ctx)
    assert final["Plaintext"] == plaintext, (
        "positive control: after CancelKeyDeletion + EnableKey the ORIGINAL ciphertext must "
        "reopen unchanged — the excursion must be lossless"
    )
    assert final["KeyId"] == key_arn, final["KeyId"]

    # --- Deletion proven as the PendingDeletion tombstone (a KMS key cannot reach not-found
    # inside the 7-day minimum window): the read by id reports PendingDeletion with a
    # DeletionDate, the key is absent from the enabled-key listing, and use is refused.
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
    tomb = _poll_until(
        lambda: kms.describe_key(KeyId=key_arn)["KeyMetadata"],
        lambda m: m["KeyState"] == "PendingDeletion" and "DeletionDate" in m,
        timeout_s=120,
        what=f"{key_arn} to report the PendingDeletion tombstone",
    )
    assert tomb["Enabled"] is False, tomb
    _poll_until(
        lambda: _enabled_keys(kms, {key_id}),
        lambda enabled: enabled == set(),
        timeout_s=120,
        what=f"{key_id} leaving the enabled-key listing",
    )
    _, message_tomb = _assert_refusal(
        _err_code(lambda: kms.encrypt(KeyId=key_arn, Plaintext=plaintext, EncryptionContext=enc_ctx)),
        ERR_INVALID_STATE, key_arn, "Encrypt on the deleted (PendingDeletion) key",
    )
    assert message_tomb == pending_message, (
        f"Encrypt on the deleted key: expected message {pending_message!r}, got {message_tomb!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
