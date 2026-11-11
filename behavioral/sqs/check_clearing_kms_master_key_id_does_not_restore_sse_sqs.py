"""clearing-kms-master-key-id-does-not-restore-sse-sqs."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "clearing-kms-master-key-id-does-not-restore-sse-sqs"
GROUP = "server-side"
SERVICES = ["sqs"]

_SSE_KEYS = ("SqsManagedSseEnabled", "KmsMasterKeyId", "KmsDataKeyReusePeriodSeconds")


def _sse(sqs, url):
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    return {k: attrs[k] for k in _SSE_KEYS if k in attrs}


def _poll(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Clearing an SSE-KMS queue's KMS key id drops both KMS attributes but leaves
    SqsManagedSseEnabled "false"; messages still round-trip, and setting it "true" restores SSE-SQS.
    """
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    name = ctx.unique_name("sim2real-behav-kmsclear-")

    key_id = kms.create_key(
        Description=name, Tags=[{"TagKey": "sim2real", "TagValue": name}]
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    url = sqs.create_queue(
        QueueName=name, Attributes={"KmsMasterKeyId": key_id}, tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    before = _sse(sqs, url)
    assert before.get("KmsMasterKeyId") == key_id, f"queue did not pick up the KMS key: {before!r}"
    assert before.get("SqsManagedSseEnabled") == "false", f"an SSE-KMS queue read {before!r}"
    assert "KmsDataKeyReusePeriodSeconds" in before, f"SSE-KMS queue missing its reuse period: {before!r}"

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"KmsMasterKeyId": ""})
    after = _poll(lambda: _sse(sqs, url), lambda s: "KmsMasterKeyId" not in s)
    assert after == {"SqsManagedSseEnabled": "false"}, (
        f"clearing KmsMasterKeyId left {after!r}, expected only SqsManagedSseEnabled 'false' "
        f"with KmsMasterKeyId and KmsDataKeyReusePeriodSeconds both gone"
    )

    body = f"after-kms-clear-{name}"
    sqs.send_message(QueueUrl=url, MessageBody=body)
    msgs = _poll(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", []),
        lambda m: len(m) > 0,
        timeout_s=30.0,
    )
    assert msgs and msgs[0]["Body"] == body, (
        f"a queue left in the cleared-KMS state must still round-trip a message; got {msgs!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"SqsManagedSseEnabled": "true"})
    restored = _poll(lambda: _sse(sqs, url), lambda s: s == {"SqsManagedSseEnabled": "true"})
    assert restored == {"SqsManagedSseEnabled": "true"}, (
        f"explicitly setting SqsManagedSseEnabled 'true' from the cleared state left {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
