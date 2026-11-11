"""sqsbatch-send-request-level-error-preempts-entry-failures-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sqsbatch-send-request-level-error-preempts-entry-failures-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Request-level code, in SQS's AWS.SimpleQueueService namespace, not the bare shape name.
ERR_IDS_NOT_DISTINCT = "AWS.SimpleQueueService.BatchEntryIdsNotDistinct"
# The per-entry code the same empty body earns once the request-level fault is repaired.
ERR_EMPTY_VALUE = "EmptyValue"

BATCH_MAX_ENTRIES = 10
# The entry whose MessageBody is empty (a per-entry fault) and the entry whose Id is a repeat
# of entry 2's (a request-level fault). Two different entries, so neither masks the other.
BAD_BODY_INDEX = 4
DUP_ID_INDEX = 7
DUP_OF_INDEX = 2


def _error_code(fn):
    """Return the botocore (Error.Code, Error.Message) raised by fn(); fail if fn() succeeds."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - botocore ClientError and friends
        resp = getattr(exc, "response", None) or {}
        code = (resp.get("Error") or {}).get("Code")
        assert code, f"raised {type(exc).__name__} with no Error.Code: {exc}"
        return code, (resp.get("Error") or {}).get("Message")
    raise AssertionError("SendMessageBatch unexpectedly SUCCEEDED; real AWS rejects this request")


def _poll(fn, pred, *, timeout_s, interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _observe(sqs, url, *, timeout_s):
    """Bodies of every distinct message that becomes visible inside timeout_s, each deleted so
    it is counted once. Always runs the full window: the window closing with nothing further
    arriving is the effect-absent evidence."""
    seen, bodies = set(), []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            if msg["MessageId"] not in seen:
                seen.add(msg["MessageId"])
                bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A batch with a repeated entry Id and an empty body is rejected wholesale with
    BatchEntryIdsNotDistinct and enqueues nothing; with only the Id repaired the same batch
    splits per entry, with EmptyValue on the empty-bodied entry.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessageBatch.html
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    observe_s = 14

    bodies = [f"preempt-body-{i}" for i in range(BATCH_MAX_ENTRIES)]
    distinct_ids = [f"e{i}" for i in range(BATCH_MAX_ENTRIES)]
    repeated_ids = list(distinct_ids)
    repeated_ids[DUP_ID_INDEX] = distinct_ids[DUP_OF_INDEX]

    def _entries(ids, *, empty_body_at):
        return [{"Id": ids[i],
                 "MessageBody": ("" if i == empty_body_at else bodies[i])}
                for i in range(BATCH_MAX_ENTRIES)]

    # Both faults at once: the request-level one must win.
    innocent = [bodies[i] for i in range(BATCH_MAX_ENTRIES)
                if i not in (BAD_BODY_INDEX, DUP_ID_INDEX)]
    code, message = _error_code(lambda: sqs.send_message_batch(
        QueueUrl=url, Entries=_entries(repeated_ids, empty_body_at=BAD_BODY_INDEX)))
    assert code == ERR_IDS_NOT_DISTINCT, (
        f"a batch with a repeated Id AND an empty body raised {code!r}; the request-level "
        f"fault must win with {ERR_IDS_NOT_DISTINCT!r} rather than degrading to a per-entry "
        f"{ERR_EMPTY_VALUE!r} split"
    )
    assert message == f"Id {distinct_ids[DUP_OF_INDEX]} repeated.", (
        f"the request-level refusal message is {message!r}"
    )

    leaked = _observe(sqs, url, timeout_s=observe_s)
    assert leaked == [], (
        f"the wholly rejected batch enqueued {leaked}; all of {innocent} were individually "
        f"valid with distinct Ids and still must not land"
    )
    depth = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=["ApproximateNumberOfMessages",
                            "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"],
        lambda a: (a["ApproximateNumberOfMessages"] == "0"
                   and a["ApproximateNumberOfMessagesNotVisible"] == "0"),
        timeout_s=30,
    )
    assert depth["ApproximateNumberOfMessages"] == "0", (
        f"queue reports {depth['ApproximateNumberOfMessages']!r} visible messages after a "
        f"wholly rejected batch"
    )
    assert depth["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"queue reports {depth['ApproximateNumberOfMessagesNotVisible']!r} in flight after a "
        f"wholly rejected batch"
    )

    # Positive control: repair only the repeated Id.
    resp = sqs.send_message_batch(
        QueueUrl=url, Entries=_entries(distinct_ids, empty_body_at=BAD_BODY_INDEX))
    succ = {e["Id"] for e in resp.get("Successful", [])}
    fail = {e["Id"]: e for e in resp.get("Failed", [])}
    want_ok = {distinct_ids[i] for i in range(BATCH_MAX_ENTRIES) if i != BAD_BODY_INDEX}
    assert succ == want_ok, (
        f"with distinct Ids the Successful list is {sorted(succ)}, expected the nine "
        f"non-empty entries {sorted(want_ok)}"
    )
    assert set(fail) == {distinct_ids[BAD_BODY_INDEX]}, (
        f"Failed Ids {sorted(fail)}, expected exactly [{distinct_ids[BAD_BODY_INDEX]!r}]"
    )
    assert fail[distinct_ids[BAD_BODY_INDEX]].get("Code") == ERR_EMPTY_VALUE, (
        f"per-entry Code is {fail[distinct_ids[BAD_BODY_INDEX]].get('Code')!r}, expected "
        f"{ERR_EMPTY_VALUE!r}; this is the fault the request-level error suppressed above"
    )
    assert fail[distinct_ids[BAD_BODY_INDEX]].get("Message") == f"No Value Found for SendMessageBatchRequestEntry.{BAD_BODY_INDEX + 1}.MessageBody.", (
        f"per-entry Message is {fail[distinct_ids[BAD_BODY_INDEX]].get('Message')!r}"
    )
    want_bodies = {bodies[i] for i in range(BATCH_MAX_ENTRIES) if i != BAD_BODY_INDEX}
    got = _observe(sqs, url, timeout_s=observe_s)
    assert set(got) == want_bodies, (
        f"the repaired batch delivered {sorted(got)}, expected the nine valid bodies "
        f"{sorted(want_bodies)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
