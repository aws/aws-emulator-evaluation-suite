"""data-key-of-custom-length-binds-a-multi-pair-context-regardless-of-order."""

from __future__ import annotations

import datetime as _dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-key-of-custom-length-binds-a-multi-pair-context-regardless-of-order"
GROUP = "e2e_workflows"
SERVICES = ["kms"]

#: KMS key-state changes are eventually consistent; each converges within this bound.
_CONVERGE_S = 40.0
_DATA_KEY_BYTES = 48
_WINDOW_DAYS = 30


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A 48-byte data key under a three-pair context decrypts with the pairs in any order but not
    with one pair missing or one extra; a disabled key refuses GenerateDataKey and Decrypt until
    re-enabled, and a key pending deletion for 30 days refuses Decrypt of its own ciphertext."""
    kms = ctx.client("kms")
    tag_spec = [{"TagKey": "sim2real-check", "TagValue": CHECK}]
    key_id = kms.create_key(KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT", Tags=tag_spec)[
        "KeyMetadata"
    ]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: _schedule_deletion(kms, _k))
    key_arn = f"arn:{_partition(ctx)}:kms:{ctx.region}:{ctx.account}:key/{key_id}"

    context = {"tenant": ctx.unique_name("t-"), "table": "orders", "région": "zürich"}
    gen = kms.generate_data_key(
        KeyId=key_id, NumberOfBytes=_DATA_KEY_BYTES, EncryptionContext=context
    )
    plaintext_key, blob = gen["Plaintext"], gen["CiphertextBlob"]
    assert len(plaintext_key) == _DATA_KEY_BYTES, (
        f"GenerateDataKey returned {len(plaintext_key)} bytes, expected {_DATA_KEY_BYTES}"
    )
    assert gen["KeyId"] == key_arn, f"GenerateDataKey KeyId {gen['KeyId']!r}, expected {key_arn!r}"
    assert plaintext_key not in blob, "the CiphertextBlob carries the data key in the clear"

    # The context is a set of pairs: the same pairs in reverse order decrypt.
    reordered = dict(reversed(list(context.items())))
    dec = kms.decrypt(CiphertextBlob=blob, EncryptionContext=reordered)
    assert dec["Plaintext"] == plaintext_key, (
        "Decrypt with the reordered context did not recover the data key"
    )
    assert dec["KeyId"] == key_arn, f"Decrypt KeyId {dec['KeyId']!r}, expected {key_arn!r}"

    # One pair missing, or one pair extra, is a different context: AWS answers an empty message.
    missing = {k: v for k, v in context.items() if k != "table"}
    extra = {**context, "stage": "blue"}
    for label, other_context in (
        ("one pair missing", missing),
        ("one extra pair", extra),
        ("no context", None),
    ):
        kwargs = {"CiphertextBlob": blob}
        if other_context is not None:
            kwargs["EncryptionContext"] = other_context
        got = _refusal(lambda kw=kwargs: kms.decrypt(**kw), f"Decrypt with {label}")
        assert got == ("InvalidCiphertextException", ""), f"Decrypt with {label}: got {got!r}"

    # Disabled: both GenerateDataKey and Decrypt are refused; re-enabled, Decrypt recovers the key.
    kms.disable_key(KeyId=key_id)
    disabled = ("DisabledException", f"{key_arn} is disabled.")
    got = _refusal(
        lambda: kms.generate_data_key(
            KeyId=key_id, NumberOfBytes=_DATA_KEY_BYTES, EncryptionContext=context
        ),
        "GenerateDataKey under a disabled key",
        converge=True,
    )
    assert got == disabled, f"GenerateDataKey under a disabled key: got {got!r}"
    got = _refusal(
        lambda: kms.decrypt(CiphertextBlob=blob, EncryptionContext=context),
        "Decrypt under a disabled key",
        converge=True,
    )
    assert got == disabled, f"Decrypt under a disabled key: got {got!r}"
    kms.enable_key(KeyId=key_id)
    again = _converge(lambda: kms.decrypt(CiphertextBlob=blob, EncryptionContext=context))
    assert again["Plaintext"] == plaintext_key, (
        "Decrypt after EnableKey did not recover the data key"
    )

    # Pending deletion for 30 days: the window and DeletionDate read back, Decrypt is refused.
    scheduled = kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=_WINDOW_DAYS)
    assert scheduled["PendingWindowInDays"] == _WINDOW_DAYS, (
        f"ScheduleKeyDeletion PendingWindowInDays {scheduled['PendingWindowInDays']!r}, expected {_WINDOW_DAYS}"
    )
    days_out = (
        scheduled["DeletionDate"] - _dt.datetime.now(_dt.timezone.utc)
    ).total_seconds() / 86400
    assert _WINDOW_DAYS - 1 <= days_out <= _WINDOW_DAYS + 1, (
        f"DeletionDate is {days_out:.2f} days out, expected {_WINDOW_DAYS} days +/- 1"
    )
    meta = _converge_value(
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda m: m["KeyState"] == "PendingDeletion" and m.get("DeletionDate") is not None,
    )
    assert (meta["KeyState"], meta.get("DeletionDate")) == (
        "PendingDeletion",
        scheduled["DeletionDate"],
    ), (
        f"DescribeKey (KeyState, DeletionDate) {(meta['KeyState'], meta.get('DeletionDate'))!r}, expected "
        f"('PendingDeletion', the DeletionDate ScheduleKeyDeletion returned {scheduled['DeletionDate']!r})"
    )
    got = _refusal(
        lambda: kms.decrypt(CiphertextBlob=blob, EncryptionContext=context),
        "Decrypt under a key pending deletion",
        converge=True,
    )
    assert got == ("KMSInvalidStateException", f"{key_arn} is pending deletion."), (
        f"Decrypt under a key pending deletion: got {got!r}"
    )


def _refusal(fn, what, *, converge=False):
    """(code, message) of the refusal fn raises, after grading its HTTP 4xx; a success raises.
    With converge, a success is retried until the key-state change propagates, then raises at
    the bound."""
    deadline = time.monotonic() + (_CONVERGE_S if converge else 0.0)
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            assert isinstance(status, int) and 400 <= status < 500, (
                f"{what} was refused with HTTP {status!r}, expected 4xx"
            )
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} should have been rejected, but it SUCCEEDED: {result!r}")
        time.sleep(1.0)


def _converge(fn):
    """fn() once the key-state change propagates: a DisabledException meanwhile is retried, and
    the last one raises at the bound."""
    deadline = time.monotonic() + _CONVERGE_S
    while True:
        try:
            return fn()
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") != "DisabledException"
                or time.monotonic() >= deadline
            ):
                raise
        time.sleep(1.0)


def _converge_value(probe, ok):
    """Re-read until ok(value) holds or the bound passes; return the last value read."""
    deadline = time.monotonic() + _CONVERGE_S
    while True:
        value = probe()
        if ok(value) or time.monotonic() >= deadline:
            return value
        time.sleep(1.0)


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _schedule_deletion(kms, key_id):
    """Teardown: schedule the key's deletion; a key the body already scheduled is left as is,
    any other refusal raises."""
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "KMSInvalidStateException":
            raise
        state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if state != "PendingDeletion":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
