"""sse-sqs-is-the-default-and-exclusive-with-sse-kms."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sse-sqs-is-the-default-and-exclusive-with-sse-kms"
GROUP = "validation"
SERVICES = ["sqs"]

BOTH_SSE = "You can use one type of server-side encryption (SSE) at one time. You can either enable KMS SSE or SQS SSE."
SSE_KEYS = ("SqsManagedSseEnabled", "KmsMasterKeyId", "KmsDataKeyReusePeriodSeconds")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A new queue defaults to SSE-SQS; requesting SSE-SQS and SSE-KMS together is refused by
    CreateQueue and SetQueueAttributes with state unchanged; switching to SSE-KMS and back updates
    the related attributes, and a body round-trips byte-exact in each mode."""
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-ssekey-"), Tags=[{"TagKey": "sim2real", "TagValue": CHECK}]
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-ssedefault-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    assert _sse(sqs, url) == {"SqsManagedSseEnabled": "true"}, f"a new queue's encryption was {_sse(sqs, url)!r}"
    _round_trip(sqs, url, "default-sse-sqs")

    refused = ctx.unique_name("sim2real-behav-bothsse-")
    err = _error(lambda: sqs.create_queue(
        QueueName=refused, Attributes={"SqsManagedSseEnabled": "true", "KmsMasterKeyId": key_id}
    ))
    assert err["Code"] == "InvalidAttributeName", f"CreateQueue with both SSE modes gave {err!r}"
    assert err["Message"] == BOTH_SSE, f"got {err['Message']!r}"
    err = _error(lambda: sqs.get_queue_url(QueueName=refused))
    assert err["Code"] == "AWS.SimpleQueueService.NonExistentQueue", f"the refused CreateQueue left a queue: {err!r}"

    err = _error(lambda: sqs.set_queue_attributes(
        QueueUrl=url, Attributes={"SqsManagedSseEnabled": "true", "KmsMasterKeyId": key_id}
    ))
    assert err["Code"] == "InvalidAttributeName", f"SetQueueAttributes with both SSE modes gave {err!r}"
    assert err["Message"] == BOTH_SSE, f"got {err['Message']!r}"
    assert _sse(sqs, url) == {"SqsManagedSseEnabled": "true"}, f"a refused update changed encryption to {_sse(sqs, url)!r}"

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"KmsMasterKeyId": key_id})
    want = {"SqsManagedSseEnabled": "false", "KmsMasterKeyId": key_id, "KmsDataKeyReusePeriodSeconds": "300"}
    got = _poll(lambda: _sse(sqs, url), lambda s: s == want, timeout_s=60.0)
    assert got == want, f"after setting KmsMasterKeyId the encryption read {got!r}"
    _round_trip(sqs, url, "sse-kms-customer-key")

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"SqsManagedSseEnabled": "true"})
    got = _poll(lambda: _sse(sqs, url), lambda s: s == {"SqsManagedSseEnabled": "true"}, timeout_s=60.0)
    assert got == {"SqsManagedSseEnabled": "true"}, f"switching back to SSE-SQS left {got!r}"
    _round_trip(sqs, url, "back-to-sse-sqs")


def _sse(sqs, url):
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    return {k: attrs[k] for k in SSE_KEYS if k in attrs}


def _round_trip(sqs, url, label):
    body = f"{label}-é中\U0001f600"
    sqs.send_message(QueueUrl=url, MessageBody=body)
    msgs = _poll(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []),
        lambda m: len(m) > 0,
        timeout_s=30.0,
    )
    assert [m["Body"] for m in msgs] == [body], f"{label}: received {[m['Body'] for m in msgs]!r}, expected [{body!r}]"
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])


def _error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
