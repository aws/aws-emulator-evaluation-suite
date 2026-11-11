"""sqsbatch-send-partial-failure-preserves-survivor-attributes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sqsbatch-send-partial-failure-preserves-survivor-attributes"
GROUP = 'state'
SERVICES = ['sqs']

ERR_EMPTY_VALUE = "EmptyValue"

BATCH_MAX_ENTRIES = 10
BAD_INDEX = 4


def _attributes(i):
    """Three MessageAttributes per entry, one of each data type, all keyed off i so the
    per-entry digests differ and a cross-entry mix-up is visible."""
    return {
        "idx": {"DataType": "Number", "StringValue": str(i)},
        "tag": {"DataType": "String", "StringValue": f"survivor-tag-{i}"},
        "blob": {"DataType": "Binary", "BinaryValue": bytes([i, i + 1, i + 2])},
    }


def _poll(fn, pred, *, timeout_s, interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _observe_with_attributes(sqs, url, *, timeout_s):
    """{body: MessageAttributes} for every distinct message visible inside timeout_s, each
    deleted so it is counted once. Always runs the full window: the window closing with
    nothing further arriving is the effect-absent evidence."""
    seen, out = set(), {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            if msg["MessageId"] not in seen:
                seen.add(msg["MessageId"])
                out[msg["Body"]] = msg.get("MessageAttributes") or {}
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """When one of ten SendMessageBatch entries fails, the nine survivors each get their own
    MD5OfMessageAttributes and come back with their String/Number/Binary attributes byte-exact,
    and the rejected entry's attributes are nowhere on the queue.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    observe_s = 16

    bodies = {i: f"attr-survivor-{i}" for i in range(BATCH_MAX_ENTRIES)}
    ids = [f"e{i}" for i in range(BATCH_MAX_ENTRIES)]
    entries = [
        {"Id": ids[i],
         "MessageBody": ("" if i == BAD_INDEX else bodies[i]),
         "MessageAttributes": _attributes(i)}
        for i in range(BATCH_MAX_ENTRIES)
    ]
    survivors = [i for i in range(BATCH_MAX_ENTRIES) if i != BAD_INDEX]

    resp = sqs.send_message_batch(QueueUrl=url, Entries=entries)
    succ = {e["Id"]: e for e in resp.get("Successful", [])}
    fail = {e["Id"]: e for e in resp.get("Failed", [])}

    assert set(succ) == {ids[i] for i in survivors}, (
        f"Successful Ids {sorted(succ)} != the nine entries with a non-empty body "
        f"{sorted(ids[i] for i in survivors)}"
    )
    assert set(fail) == {ids[BAD_INDEX]}, (
        f"Failed Ids {sorted(fail)}, expected exactly [{ids[BAD_INDEX]!r}]"
    )
    assert fail[ids[BAD_INDEX]].get("Code") == ERR_EMPTY_VALUE, (
        f"Failed Code is {fail[ids[BAD_INDEX]].get('Code')!r}, expected {ERR_EMPTY_VALUE!r}"
    )
    assert fail[ids[BAD_INDEX]].get("Message") == f"No Value Found for SendMessageBatchRequestEntry.{BAD_INDEX + 1}.MessageBody.", (
        f"Failed Message is {fail[ids[BAD_INDEX]].get('Message')!r}"
    )

    # Every survivor got its OWN attribute digest, and the digests differ because the
    # attributes differ -- a target that computes one digest for the batch, or reuses the body
    # digest, diverges here.
    attr_md5 = {}
    for i in survivors:
        entry = succ[ids[i]]
        digest = entry.get("MD5OfMessageAttributes") or ""
        assert len(digest) == 32 and all(c in "0123456789abcdef" for c in digest), (
            f"Successful[{ids[i]!r}].MD5OfMessageAttributes is not a 32-char hex digest: "
            f"{digest!r}"
        )
        assert digest != entry.get("MD5OfMessageBody"), (
            f"Successful[{ids[i]!r}] reused MD5OfMessageBody as MD5OfMessageAttributes: "
            f"{digest!r}"
        )
        attr_md5[ids[i]] = digest
    assert len(set(attr_md5.values())) == len(survivors), (
        f"the nine survivors produced {len(set(attr_md5.values()))} distinct attribute digests, "
        f"expected {len(survivors)}: {attr_md5}"
    )

    # --- the effect, read back off the data plane ------------------------------------------
    got = _observe_with_attributes(sqs, url, timeout_s=observe_s)
    assert set(got) == {bodies[i] for i in survivors}, (
        f"received bodies {sorted(got)}, expected exactly the nine survivors "
        f"{sorted(bodies[i] for i in survivors)}"
    )
    for i in survivors:
        want = _attributes(i)
        have = got[bodies[i]]
        assert set(have) == set(want), (
            f"{bodies[i]!r} came back with attribute names {sorted(have)}, expected "
            f"{sorted(want)}"
        )
        assert have["idx"]["DataType"] == "Number" and have["idx"]["StringValue"] == str(i), (
            f"{bodies[i]!r} Number attribute came back as {have['idx']!r}, expected "
            f"{want['idx']!r}"
        )
        assert (have["tag"]["DataType"] == "String"
                and have["tag"]["StringValue"] == want["tag"]["StringValue"]), (
            f"{bodies[i]!r} String attribute came back as {have['tag']!r}, expected "
            f"{want['tag']!r}"
        )
        assert have["blob"]["DataType"] == "Binary", (
            f"{bodies[i]!r} blob attribute DataType came back as "
            f"{have['blob']['DataType']!r}, expected 'Binary'"
        )
        # botocore decodes the transport's base64 for us, so this compares raw bytes to raw
        # bytes -- a target that returns the encoded form fails here rather than silently.
        assert bytes(have["blob"]["BinaryValue"]) == want["blob"]["BinaryValue"], (
            f"{bodies[i]!r} Binary attribute came back as "
            f"{bytes(have['blob']['BinaryValue'])!r}, expected "
            f"{want['blob']['BinaryValue']!r}"
        )

    # --- effect absent: the rejected entry's attributes never reached the queue -------------
    seen_idx = {int(a["idx"]["StringValue"]) for a in got.values()}
    assert seen_idx == set(survivors), (
        f"attribute idx values on the queue are {sorted(seen_idx)}, expected {survivors}; "
        f"idx={BAD_INDEX} belongs to the entry AWS reported Failed and must be absent"
    )
    remaining = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: v == "0",
        timeout_s=30,
    )
    assert remaining == "0", (
        f"queue still reports {remaining!r} visible messages after all nine were drained"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
