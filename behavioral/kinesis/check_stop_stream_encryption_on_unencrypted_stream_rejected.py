"""stop-stream-encryption-on-unencrypted-stream-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(c, name)
    return name


def _summary(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]


CHECK = "stop-stream-encryption-on-unencrypted-stream-rejected"
GROUP = "encryption"
SERVICES = ["kinesis"]


def _start_encryption_with_new_key(ctx, client, stream_name, key_id):
    """StartStreamEncryption with a key created moments before; Kinesis may not resolve a new
    key for a few seconds, so KMSNotFoundException is retried for up to 60 s, within the budget."""
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(0.0, min(60.0, left - 10.0)))
    while True:
        try:
            return client.start_stream_encryption(
                StreamName=stream_name, EncryptionType="KMS", KeyId=key_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KMSNotFoundException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopStreamEncryption on an unencrypted stream fails with InvalidArgumentException instead
    of no-opping, leaving EncryptionType NONE; it succeeds once the stream is KMS-encrypted."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)

    before = _summary(c, name)
    assert before["EncryptionType"] == "NONE", (
        f"expected a freshly created stream to start EncryptionType=NONE, got {before['EncryptionType']}"
    )

    kms = ctx.client("kms")
    key_id = kms.create_key(Description=name)["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    try:
        c.stop_stream_encryption(StreamName=name, EncryptionType="KMS", KeyId=key_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"StopStreamEncryption on unencrypted stream {name} unexpectedly succeeded"
        )

    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException stopping encryption on an unencrypted stream, got {code}"
    )
    expected_message = "Cannot stop encrypting an unencrypted stream."
    assert message == expected_message, (
        f"StopStreamEncryption on unencrypted stream {name} answered {message!r}, "
        f"expected {expected_message!r}"
    )

    after = _summary(c, name)
    assert after["EncryptionType"] == "NONE", (
        f"rejected StopStreamEncryption should leave EncryptionType at NONE, got {after['EncryptionType']}"
    )
    assert after["StreamStatus"] == "ACTIVE", (
        f"rejected StopStreamEncryption moved the stream to {after['StreamStatus']}; "
        f"a rejected request must not start an update"
    )

    # Positive control: the same operation succeeds once the stream really is encrypted.
    _start_encryption_with_new_key(ctx, c, name, key_id)
    encrypted = _poll(
        lambda: _summary(c, name),
        lambda d: d["EncryptionType"] == "KMS",
        timeout_s=120, interval_s=3,
        description="EncryptionType reaches KMS after StartStreamEncryption",
    )
    c.stop_stream_encryption(StreamName=name, EncryptionType="KMS", KeyId=encrypted["KeyId"])
    disabled = _poll(
        lambda: _summary(c, name),
        lambda d: d["EncryptionType"] == "NONE",
        timeout_s=120, interval_s=3,
        description="EncryptionType returns to NONE after StopStreamEncryption",
    )
    assert disabled["EncryptionType"] == "NONE", (
        f"expected StopStreamEncryption on a genuinely encrypted stream to succeed, "
        f"got EncryptionType={disabled['EncryptionType']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
