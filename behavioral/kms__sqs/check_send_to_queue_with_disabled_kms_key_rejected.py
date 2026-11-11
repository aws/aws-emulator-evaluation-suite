"""send-to-queue-with-disabled-kms-key-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-to-queue-with-disabled-kms-key-rejected"
GROUP = 'errors'
SERVICES = ['kms', 'sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "sqs-disabled-cmk"}
_KMS_TAGS = [{"TagKey": k, "TagValue": v} for k, v in _TAGS.items()]

# The SQS model declares com.amazonaws.sqs#KmsDisabled with the awsQueryError code
# "KMS.DisabledException", which is the code SQS returns for a disabled key.
ERR_KMS_DISABLED = "KMS.DisabledException"
# 60 is the API MINIMUM for KmsDataKeyReusePeriodSeconds and it is set for exactly one reason: SQS
# may keep reusing a cached data key for the whole period, so a send made right after disable_key
# legitimately SUCCEEDS. The retry loop below must outlast the cache or the check reports a false
# negative.
_REUSE_S = 60
_DISABLE_CEILING_S = 150
_RESTORE_CEILING_S = 90


# What _err reports for a call that SUCCEEDED: a value no error code can equal.
_ACCEPTED = "<call succeeded>"


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises, or (_ACCEPTED, "").

    A send that SUCCEEDS while the key is disabled is the over-permissive failure this check
    exists to catch, so it is reported as a value no code can equal, never as a falsy code.
    """
    try:
        fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message", "")
    return _ACCEPTED, ""


def _round_trip(sqs, url, body, *, timeout_s):
    """Send `body`, receive it, delete it, and return the received body (or None)."""
    sqs.send_message(QueueUrl=url, MessageBody=body)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5,
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            return m["Body"]
    return None


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """SendMessage to a queue under a customer-managed KMS key fails with KMS.DisabledException once
    the key is disabled and enqueues nothing; re-enabling the key restores SendMessage and a
    byte-exact ReceiveMessage, after a byte-exact control round trip before the disable."""
    kms = ctx.client("kms")
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    body = f"cmk-{token}|multibyte: 日本語 éü \U0001f510|tab:\there"

    key = kms.create_key(
        Description=f"sim2real-xsvc-sqs-disabled-cmk-{token}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=_KMS_TAGS,
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    # Registered immediately, and LIFO runs it LAST: 7 days is the minimum PendingWindowInDays --
    # KMS offers no immediate delete.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    # Registered second so it runs BEFORE the deletion is scheduled: a key left disabled would make
    # a leaked queue permanently unreadable, and re-enabling is idempotent.
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key_id))

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-"),
        Attributes={"KmsMasterKeyId": key_arn,
                    "KmsDataKeyReusePeriodSeconds": str(_REUSE_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    assert attrs.get("KmsMasterKeyId") in (key_arn, key_id), (
        f"the queue is not encrypted with the CMK this check created, so disabling that key proves "
        f"nothing: KmsMasterKeyId={attrs.get('KmsMasterKeyId')!r}, expected {key_arn!r}"
    )
    assert attrs.get("KmsDataKeyReusePeriodSeconds") == str(_REUSE_S), (
        f"the data-key reuse period was not set to the {_REUSE_S}s minimum, so the retry budget "
        f"below may be shorter than the cache: {attrs.get('KmsDataKeyReusePeriodSeconds')!r}"
    )

    # --- control FIRST: the encrypted queue works before anything is broken ------------
    control_body = _round_trip(sqs, url, body, timeout_s=60)
    assert control_body == body, (
        f"the CMK-encrypted queue did not round-trip the body before the key was disabled, so the "
        f"refusal below cannot be attributed to the key state: got {control_body!r}"
    )

    # --- break exactly one thing ------------------------------------------------------
    kms.disable_key(KeyId=key_id)

    # A send may keep succeeding for up to KmsDataKeyReusePeriodSeconds while SQS reuses its cached
    # data key. Each accepted send is drained so the effect-absent leg below starts from an empty
    # queue; only the send made once the disable is demonstrably in force is used for it.
    accepted: list[str] = []
    code = message = None
    deadline = time.monotonic() + _DISABLE_CEILING_S
    attempt = 0
    while True:
        attempt += 1
        probe = f"probe-{attempt}-{token}"
        code, message = _err(lambda: sqs.send_message(QueueUrl=url, MessageBody=probe))
        if code != _ACCEPTED:
            break
        accepted.append(probe)
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    # message varies: SQS relays KMS's text, which embeds the request id of SQS's own KMS call.
    assert code == ERR_KMS_DISABLED, (
        f"SendMessage to a queue whose CMK is disabled must fail with {ERR_KMS_DISABLED!r} within "
        f"{_DISABLE_CEILING_S}s and {attempt} attempts, got {code!r}: {message!r} ({_ACCEPTED!r} means "
        f"the send SUCCEEDED, i.e. the disabled key was never consulted)"
    )

    # --- effect absent: a refused send left nothing behind ----------------------------
    #
    # ReceiveMessage needs the key too and raises the same KMS.DisabledException, so the queue
    # cannot be drained while the key is disabled. The effect-absent leg is "the depth does not
    # rise", read through GetQueueAttributes, which does not touch KMS.
    def _depth():
        return sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"].get("ApproximateNumberOfMessages", "?")

    want = str(len(accepted))
    settled = "?"
    settle_deadline = time.monotonic() + 90
    while time.monotonic() < settle_deadline:
        settled = _depth()
        if settled == want:
            break
        time.sleep(2.0)
    assert settled == want, (
        f"the queue holds {settled!r} messages but exactly {want} sends were ACCEPTED before the "
        f"disable took hold, so a later depth reading cannot attribute a change to the refused "
        f"send"
    )

    denied_code, denied_message = _err(lambda: sqs.send_message(
        QueueUrl=url, MessageBody=f"denied-{token}"))
    # message varies: same relayed KMS text with a per-call request id as above.
    assert denied_code == ERR_KMS_DISABLED, (
        f"the disabled key stopped being consulted between two consecutive sends: {denied_code!r}: "
        f"{denied_message!r}"
    )

    # Watch the depth for a while rather than reading it once: ApproximateNumberOfMessages is
    # eventually consistent, so a single immediate read would not have caught up with an enqueue
    # that DID happen.
    #
    # The assertion is an upper bound, not equality: the approximate counter can read below the
    # true depth, so only an increase means the refused send enqueued something. The settle loop
    # above has shown the counter does reach `want`.
    observed = set()
    watch_deadline = time.monotonic() + 30
    while time.monotonic() < watch_deadline:
        observed.add(_depth())
        time.sleep(2.0)
    assert all(d.isdigit() and int(d) <= len(accepted) for d in observed), (
        f"a send refused for a disabled KMS key still enqueued something: "
        f"ApproximateNumberOfMessages was observed at {sorted(observed)!r} after the refusal, and "
        f"only {len(accepted)} sends were ever accepted"
    )

    # --- control again: repair the one broken thing and the refusal reverses -----------
    kms.enable_key(KeyId=key_id)
    restored_code = restored_msg = None
    restore_deadline = time.monotonic() + _RESTORE_CEILING_S
    while True:
        restored_code, restored_msg = _err(lambda: sqs.send_message(
            QueueUrl=url, MessageBody=f"restore-probe-{token}"))
        if restored_code == _ACCEPTED or time.monotonic() >= restore_deadline:
            break
        time.sleep(5.0)
    assert restored_code == _ACCEPTED, (
        f"re-enabling the CMK did not restore SendMessage within {_RESTORE_CEILING_S}s: still "
        f"{restored_code!r}: {restored_msg!r} -- the check cannot pass by refusing every send"
    )

    # Now that the key is usable again, drain everything the cache let through plus the restore
    # probe, so the final round trip below reads its OWN message rather than an earlier one. The
    # drain tolerates a ClientError because the enable propagates through the same data-key cache.
    drain_deadline = time.monotonic() + _RESTORE_CEILING_S
    empties = 0
    while empties < 2 and time.monotonic() < drain_deadline:
        try:
            batch = sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
            ).get("Messages", [])
        except ClientError:
            time.sleep(3.0)
            continue
        if not batch:
            empties += 1
            continue
        empties = 0
        for m in batch:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert empties >= 2, (
        f"the CMK-encrypted queue could not be drained within {_RESTORE_CEILING_S}s of re-enabling "
        f"the key, so the round trip below would read an earlier message"
    )

    restored_body = _round_trip(sqs, url, body, timeout_s=60)
    assert restored_body == body, (
        f"re-enabling the key restored SendMessage but not the round trip -- the body could not be "
        f"decrypted byte-exact: got {restored_body!r}, sent {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
