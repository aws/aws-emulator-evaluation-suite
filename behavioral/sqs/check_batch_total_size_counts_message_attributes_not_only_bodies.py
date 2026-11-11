"""batch-total-size-counts-message-attributes-not-only-bodies."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-total-size-counts-message-attributes-not-only-bodies"
GROUP = "limits"
SERVICES = ["sqs"]

# A fixed API constant (the documented floor of MaximumMessageSize's own allowed range), used
# only to sanity-check what the queue reports -- never assumed to BE the batch bound.
MIN_PLAUSIBLE_LIMIT = 262144
ERR_BATCH_TOO_LONG = "AWS.SimpleQueueService.BatchRequestTooLong"


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the batch to be refused, but it succeeded: {result!r}")


def _poll(fn, pred, *, timeout_s, interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _drain(sqs, url, *, timeout_s):
    seen, bodies = set(), []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                        WaitTimeSeconds=1).get("Messages", []):
            if msg["MessageId"] not in seen:
                seen.add(msg["MessageId"])
                bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """SendMessageBatch's aggregate size bound counts MessageAttributes, not only bodies: two
    tiny-body entries with large attributes are refused with BatchRequestTooLong; none enqueue.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-battrsize-"),
        tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    limit = int(sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["MaximumMessageSize"]
    )["Attributes"]["MaximumMessageSize"])
    assert limit >= MIN_PLAUSIBLE_LIMIT, (
        f"MaximumMessageSize={limit} is below the smallest bound SQS documents "
        f"({MIN_PLAUSIBLE_LIMIT}); the queue attribute cannot be trusted as the batch bound"
    )

    # Each entry: a 5-byte body plus one String attribute named "blob" (4 bytes) whose value is
    # sized so one entry alone -- body + name + "String" (6) + value -- stays under the limit
    # (individually legal), but two entries together exceed it.
    attr_value_len = limit // 2 + 100
    body = "small"
    attr_name = "blob"

    def entry(entry_id: str) -> dict:
        return {
            "Id": entry_id,
            "MessageBody": body,
            "MessageAttributes": {
                attr_name: {"DataType": "String", "StringValue": "x" * attr_value_len}
            },
        }

    per_entry_bytes = len(body) + len(attr_name) + len("String") + attr_value_len
    assert per_entry_bytes < limit, "test entry must be individually legal"
    entries = [entry("e0"), entry("e1")]
    total_bytes = per_entry_bytes * 2
    assert total_bytes > limit, "batch must exceed the limit once both entries are summed"
    # Total BODY bytes alone -- what a body-only accounting would see -- stays tiny, so a
    # refusal here can only be explained by attributes counting toward the aggregate too.
    total_body_bytes = sum(len(e["MessageBody"]) for e in entries)
    assert total_body_bytes < 100, f"test body total {total_body_bytes} is not tiny as intended"

    code, message = _err(lambda: sqs.send_message_batch(QueueUrl=url, Entries=entries))
    assert code == ERR_BATCH_TOO_LONG, (
        f"expected {ERR_BATCH_TOO_LONG} for a {total_bytes}-byte (attribute-driven) batch of "
        f"2 individually-legal {per_entry_bytes}-byte entries with only {total_body_bytes} "
        f"total body bytes, got {code!r} ({message!r})"
    )
    expected_message = (
        f"Batch requests cannot be longer than {limit} bytes. You have sent {total_bytes} bytes."
    )
    assert message == expected_message, (
        f"expected refusal message {expected_message!r}, got {message!r}"
    )

    # All-or-nothing: neither entry enqueued.
    depth = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: v != "0",
        timeout_s=8,
    )
    assert depth == "0", f"rejected batch enqueued something: ApproximateNumberOfMessages={depth}"
    leaked = _drain(sqs, url, timeout_s=10)
    assert leaked == [], f"rejected batch delivered {len(leaked)} message(s): {leaked!r}"

    # The same entries sent one at a time succeed, so the refusal was about the aggregate.
    for e in entries:
        resp = sqs.send_message_batch(QueueUrl=url, Entries=[e])
        assert not resp.get("Failed"), f"split send of {e['Id']!r} failed: {resp.get('Failed')}"
        assert [x["Id"] for x in resp["Successful"]] == [e["Id"]], (
            f"split send of {e['Id']!r} answered {resp['Successful']!r}"
        )
    delivered = _drain(sqs, url, timeout_s=20)
    assert sorted(delivered) == [body, body], (
        f"split sends delivered {delivered!r}, expected two {body!r} messages"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
