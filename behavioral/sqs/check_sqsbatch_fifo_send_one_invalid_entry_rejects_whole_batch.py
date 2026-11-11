"""sqsbatch-fifo-send-one-invalid-entry-rejects-whole-batch."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "sqsbatch-fifo-send-one-invalid-entry-rejects-whole-batch"
GROUP = 'errors'
SERVICES = ['sqs']

# Top-level Error.Code real AWS raises when a FIFO SendMessageBatch carries a malformed entry.
ERR_INVALID_PARAMETER_VALUE = "InvalidParameterValue"
# Per-entry BatchResultErrorEntry.Code the SAME malformation produces on a standard queue.
ERR_EMPTY_VALUE = "EmptyValue"

BATCH_MAX_ENTRIES = 10
BAD_INDEX = 4


def _error_code(fn):
    """Return the botocore (Error.Code, Error.Message) raised by fn(); raise if it succeeds."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - botocore ClientError and friends
        resp = getattr(exc, "response", None) or {}
        code = (resp.get("Error") or {}).get("Code")
        assert code, f"raised {type(exc).__name__} with no Error.Code: {exc}"
        return code, (resp.get("Error") or {}).get("Message")
    raise AssertionError("call unexpectedly SUCCEEDED; real AWS rejects this request")


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
    """Bodies of every distinct message visible within timeout_s, in arrival order, each deleted.

    The full window always runs, so an empty result is effect-absent evidence.
    """
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
    """One empty-bodied entry rejects a whole FIFO SendMessageBatch (InvalidParameterValue, nothing
    enqueued), while on a standard queue it is one Failed entry (EmptyValue) and nine siblings land.
    """
    sqs = ctx.client("sqs")
    fifo_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false",
                    "VisibilityTimeout": "30"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_url))
    std_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": "30"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=std_url))

    group = "sim2real-group-" + uuid.uuid4().hex[:8]
    observe_s = 14
    absent_s = 14

    def _fifo_entries(bodies):
        # A fresh MessageDeduplicationId per entry per call: dedup must never be what makes a
        # sibling invisible, or the effect-absent assertion below would prove nothing.
        return [{"Id": f"e{i}", "MessageBody": bodies[i], "MessageGroupId": group,
                 "MessageDeduplicationId": uuid.uuid4().hex}
                for i in range(BATCH_MAX_ENTRIES)]

    # Positive control: a wholly valid full-width FIFO batch is accepted in full.
    ctl_bodies = [f"fifo-control-{i}" for i in range(BATCH_MAX_ENTRIES)]
    control = sqs.send_message_batch(QueueUrl=fifo_url, Entries=_fifo_entries(ctl_bodies))
    ctl_ok = {e["Id"] for e in control.get("Successful", [])}
    assert ctl_ok == {f"e{i}" for i in range(BATCH_MAX_ENTRIES)}, (
        f"valid FIFO batch Successful Ids {sorted(ctl_ok)}, expected all ten"
    )
    assert not control.get("Failed"), f"valid FIFO batch reported {control.get('Failed')!r}"
    for entry in control["Successful"]:
        assert entry.get("SequenceNumber"), (
            f"FIFO Successful entry {entry['Id']!r} carries no SequenceNumber: {entry!r}"
        )
    # Within one message group FIFO order is guaranteed, so arrival order is assertable here.
    ctl_order = _observe(sqs, fifo_url, timeout_s=observe_s)
    assert ctl_order == ctl_bodies, (
        f"FIFO group {group!r} delivered {ctl_order}, expected send order {ctl_bodies}"
    )

    # Break exactly one thing: entry 4 of 10 carries an empty MessageBody.
    bodies = [("" if i == BAD_INDEX else f"fifo-must-not-enqueue-{i}")
              for i in range(BATCH_MAX_ENTRIES)]
    siblings = [b for i, b in enumerate(bodies) if i != BAD_INDEX]

    code, message = _error_code(lambda: sqs.send_message_batch(
        QueueUrl=fifo_url, Entries=_fifo_entries(bodies)))
    assert code == ERR_INVALID_PARAMETER_VALUE, (
        f"FIFO SendMessageBatch with one empty-bodied entry raised {code!r}, expected a "
        f"whole-request {ERR_INVALID_PARAMETER_VALUE!r}"
    )
    assert message == f"No Value Found for SendMessageBatchRequestEntry.{BAD_INDEX + 1}.MessageBody.", (
        f"FIFO SendMessageBatch refusal message is {message!r}"
    )

    # Effect absent: not one of the nine valid siblings reached the FIFO queue.
    leaked = _observe(sqs, fifo_url, timeout_s=absent_s)
    assert leaked == [], (
        f"the rejected FIFO batch enqueued {leaked}; a whole-request rejection must enqueue "
        f"nothing, and every one of {siblings} was individually valid"
    )
    depth = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=fifo_url,
            AttributeNames=["ApproximateNumberOfMessages",
                            "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"],
        lambda a: (a["ApproximateNumberOfMessages"] == "0"
                   and a["ApproximateNumberOfMessagesNotVisible"] == "0"),
        timeout_s=30,
    )
    assert depth["ApproximateNumberOfMessages"] == "0", (
        f"FIFO queue reports {depth['ApproximateNumberOfMessages']!r} visible messages after a "
        f"wholly rejected batch"
    )
    assert depth["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"FIFO queue reports {depth['ApproximateNumberOfMessagesNotVisible']!r} in flight after "
        f"a wholly rejected batch"
    )

    # Contrast: the same malformation on a standard queue fails per entry.
    std_bodies = [("" if i == BAD_INDEX else f"std-keeps-{i}") for i in range(BATCH_MAX_ENTRIES)]
    std_siblings = {b for i, b in enumerate(std_bodies) if i != BAD_INDEX}
    std_resp = sqs.send_message_batch(
        QueueUrl=std_url,
        Entries=[{"Id": f"e{i}", "MessageBody": std_bodies[i]}
                 for i in range(BATCH_MAX_ENTRIES)],
    )
    std_ok = {e["Id"] for e in std_resp.get("Successful", [])}
    std_fail = {e["Id"]: e for e in std_resp.get("Failed", [])}
    assert std_ok == {f"e{i}" for i in range(BATCH_MAX_ENTRIES) if i != BAD_INDEX}, (
        f"standard-queue Successful Ids {sorted(std_ok)} != the nine valid entries"
    )
    assert set(std_fail) == {f"e{BAD_INDEX}"}, (
        f"standard-queue Failed Ids {sorted(std_fail)}, expected exactly ['e{BAD_INDEX}']"
    )
    assert std_fail[f"e{BAD_INDEX}"].get("Code") == ERR_EMPTY_VALUE, (
        f"standard-queue Failed Code is {std_fail[f'e{BAD_INDEX}'].get('Code')!r}, expected "
        f"{ERR_EMPTY_VALUE!r} -- a per-entry code, not the whole-request "
        f"{ERR_INVALID_PARAMETER_VALUE!r} FIFO gives"
    )
    assert std_fail[f"e{BAD_INDEX}"].get("Message") == f"No Value Found for SendMessageBatchRequestEntry.{BAD_INDEX + 1}.MessageBody.", (
        f"standard-queue Failed Message is {std_fail[f'e{BAD_INDEX}'].get('Message')!r}"
    )
    assert std_fail[f"e{BAD_INDEX}"].get("SenderFault") is True, (
        f"standard-queue Failed SenderFault is "
        f"{std_fail[f'e{BAD_INDEX}'].get('SenderFault')!r}, expected True"
    )
    std_got = _observe(sqs, std_url, timeout_s=observe_s)
    assert set(std_got) == std_siblings, (
        f"standard queue delivered {sorted(std_got)}, expected exactly the nine valid bodies "
        f"{sorted(std_siblings)} -- the per-entry model must enqueue the siblings that FIFO "
        f"refuses"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
