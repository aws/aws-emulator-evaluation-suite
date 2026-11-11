"""server-side-sse-kms-transparent-round-trip."""
from __future__ import annotations

import hashlib
import time

from behavioral_harness import tags

CHECK = "server-side-sse-kms-transparent-round-trip"
GROUP = "server-side"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With SSE-KMS set to a customer managed key via SetQueueAttributes, bodies and attributes
    round-trip unchanged and MD5OfMessageBody/MD5OfBody are digests of the plaintext body."""
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    name = ctx.unique_name("sim2real-behav-ssekms-")
    key_id = kms.create_key(
        Description=name, Tags=[{"TagKey": "sim2real", "TagValue": name}]
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"KmsMasterKeyId": key_id})

    configured = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["KmsMasterKeyId"])[
        "Attributes"
    ]["KmsMasterKeyId"]
    assert configured == key_id, f"expected KmsMasterKeyId {key_id!r}, got {configured!r}"

    body = "encrypted-at-rest-but-transparent-🔒"
    # SDKs verify these MD5s client-side, so a ciphertext digest surfaces as a checksum error.
    want_body_md5 = hashlib.md5(body.encode("utf-8")).hexdigest()
    sent = sqs.send_message(
        QueueUrl=url,
        MessageBody=body,
        MessageAttributes={"Tier": {"DataType": "String", "StringValue": "gold"}},
    )
    assert sent["MD5OfMessageBody"] == want_body_md5, (
        f"SendMessage's MD5OfMessageBody on a KMS-encrypted queue must be the digest of the "
        f"PLAINTEXT body: got {sent['MD5OfMessageBody']!r}, computed {want_body_md5!r}"
    )

    received = _poll_for_message(ctx, url)
    assert received["Body"] == body
    assert received["MD5OfBody"] == want_body_md5, (
        f"ReceiveMessage's MD5OfBody on a KMS-encrypted queue must be the digest of the "
        f"PLAINTEXT body, not of the ciphertext: got {received['MD5OfBody']!r}, computed "
        f"{want_body_md5!r}"
    )
    assert received["MessageAttributes"]["Tier"]["StringValue"] == "gold"
    sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])


def _poll_for_message(ctx, url, timeout_s=30.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        msgs = resp.get("Messages", [])
        if msgs:
            return msgs[0]
    raise AssertionError("no message received within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
