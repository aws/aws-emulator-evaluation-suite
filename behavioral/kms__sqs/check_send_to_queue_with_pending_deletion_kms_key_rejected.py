"""send-to-queue-with-pending-deletion-kms-key-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-to-queue-with-pending-deletion-kms-key-rejected"
GROUP = "errors"
SERVICES = ["kms", "sqs"]

_QUEUE_TAGS = {"sim2real": "sqs-pending-deletion-cmk"}
_KMS_TAGS = [{"TagKey": "sim2real", "TagValue": "sqs-pending-deletion-cmk"}]

ERR_INVALID_STATE = "KMS.InvalidStateException"
_RESTORE_CEILING_S = 120


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _receive(sqs, url) -> list:
    """Bodies received (and deleted) in one short long-poll."""
    out = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                 WaitTimeSeconds=1).get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        out.append(m["Body"])
    return out


def _latency(observe, *, budget_s: float = 60.0, poll_s: float = 1.0):
    """``(seconds, result)`` until ``observe()`` first returns something truthy."""
    start = time.monotonic()
    while True:
        result = observe()
        if result:
            return time.monotonic() - start, result
        if time.monotonic() - start > budget_s:
            raise AssertionError(f"the positive control saw nothing in {budget_s}s")
        time.sleep(poll_s)


def _absent_for(observe, latency_s: float, *, factor: float = 3.0, floor_s: float = 10.0,
                poll_s: float = 1.0) -> list:
    """Everything ``observe()`` returned over ``max(floor_s, factor * latency_s)`` seconds."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _pending_message(key_arn: str, message: str) -> str:
    """The text SQS relays for a pending-deletion CMK, rebuilt from the key ARN.

    The one value the check cannot know is the request id of SQS's own call to KMS, so it is
    read out of the message, required to be a UUID, and substituted back; every other character
    of the expected text is fixed.
    """
    marker = "; Request ID: "
    start = message.find(marker)
    end = message.find(";", start + len(marker)) if start >= 0 else -1
    request_id = message[start + len(marker):end] if start >= 0 and end > start else ""
    try:
        uuid.UUID(request_id)
    except ValueError:
        request_id = "<no request id>"
    return (
        f"{key_arn} is pending deletion. (Service: AWSKMS; Status Code: 400; Error Code: "
        f"KMSInvalidStateException; Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue under a customer-managed key pending deletion refuses SendMessage with
    KMS.InvalidStateException naming the key and enqueues nothing; after CancelKeyDeletion (the key
    stays Disabled) and EnableKey it delivers byte-exact again."""
    kms = ctx.client("kms")
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-xsvc-sqs-pending-cmk-"),
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=_KMS_TAGS,
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    # LIFO runs this last. KMSInvalidStateException here means the key is already pending.
    ctx.on_cleanup(_teardown(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7),
        "NotFoundException", "KMSInvalidStateException",
    ))

    control_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-pdctl-"),
        Attributes={"KmsMasterKeyId": key_arn},
        tags=_QUEUE_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=control_url),
                             "AWS.SimpleQueueService.NonExistentQueue"))

    # --- positive control: the key encrypts for SQS before anything is broken -----------
    control_body = f"control-{token}|multibyte: 日本語 éü"
    sqs.send_message(QueueUrl=control_url, MessageBody=control_body)
    latency, got = _latency(lambda: _receive(sqs, control_url))
    assert got == [control_body], (
        f"the CMK-encrypted control queue did not round-trip its body, so a refusal below could "
        f"not be attributed to the key state: got {got!r}"
    )

    # --- break exactly one thing: schedule the key's deletion ---------------------------
    scheduled = kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    assert scheduled["KeyState"] == "PendingDeletion", (
        f"ScheduleKeyDeletion answered KeyState {scheduled.get('KeyState')!r}"
    )

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-pdq-"),
        Attributes={"KmsMasterKeyId": key_arn},
        tags=_QUEUE_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["KmsMasterKeyId"])["Attributes"]
    assert attrs.get("KmsMasterKeyId") == key_arn, (
        f"the queue is not encrypted with the pending-deletion key, so the refusal proves nothing: "
        f"KmsMasterKeyId={attrs.get('KmsMasterKeyId')!r}"
    )

    refused_body = f"refused-{token}"
    code, msg = _err(lambda: sqs.send_message(QueueUrl=url, MessageBody=refused_body))
    assert code == ERR_INVALID_STATE, (
        f"SendMessage to a queue whose CMK is pending deletion must be refused "
        f"{ERR_INVALID_STATE!r}, got {code!r}: {msg!r}"
    )
    expected = _pending_message(key_arn, msg)
    assert msg == expected, f"expected the message {expected!r}, got {msg!r}"

    # --- effect absent: the refused send enqueued nothing ------------------------------
    seen = _absent_for(lambda: _receive(sqs, url), latency)
    assert seen == [], f"{len(seen)} message(s) arrived from a refused send: {seen!r}"
    depth = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]
    assert depth.get("ApproximateNumberOfMessages") == "0", (
        f"the refused send left the queue at depth {depth.get('ApproximateNumberOfMessages')!r}"
    )

    # --- repair: cancel the deletion (the key comes back Disabled) and re-enable it ------
    cancelled = kms.cancel_key_deletion(KeyId=key_id)
    assert cancelled["KeyId"] == key_arn, f"CancelKeyDeletion answered for {cancelled['KeyId']!r}"
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"a cancelled deletion leaves the key Disabled, got {state!r}"
    kms.enable_key(KeyId=key_id)

    restored_body = f"restored-{token}|tab:\there"
    restored = None
    deadline = time.monotonic() + _RESTORE_CEILING_S
    while restored is None:
        try:
            restored = sqs.send_message(QueueUrl=url, MessageBody=restored_body)
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"re-enabling the CMK did not restore SendMessage within "
                    f"{_RESTORE_CEILING_S}s: still {exc.response['Error']!r}"
                ) from exc
            time.sleep(5)
    _, delivered = _latency(lambda: _receive(sqs, url))
    assert delivered == [restored_body], (
        f"after the key was restored the queue delivered {delivered!r}, expected exactly the "
        f"restored body and nothing from the refused send"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
