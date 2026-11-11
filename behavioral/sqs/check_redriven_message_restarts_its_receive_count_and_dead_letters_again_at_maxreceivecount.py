"""redriven-message-restarts-its-receive-count-and-dead-letters-again-at-maxreceivecount."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "redriven-message-restarts-its-receive-count-and-dead-letters-again-at-maxreceivecount"
GROUP = "visibility_dlq"
SERVICES = ["sqs"]

_MAX_RECEIVE_COUNT = 2
_MOVE_S = 40.0  # bounded wait for each asynchronous source -> DLQ move
_TASK_S = 40.0  # bounded wait for the message move task to settle
_COUNTER_S = 40.0  # bounded wait for the approximate counters to converge

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "redriven-receive-count",
}


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _receive(sqs, url, *, wait_s=2):
    """One ReceiveMessage with the system attributes this check reads. Never swallows errors."""
    return sqs.receive_message(
        QueueUrl=url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=wait_s,
        MessageSystemAttributeNames=["All"],
    ).get("Messages", [])


def _await_delivery(sqs, url, *, token, timeout_s, what):
    """Bounded poll until the tokened message is delivered from `url`; RAISES on the deadline."""
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        msgs = _receive(sqs, url)
        last = [(m["Body"], m["Attributes"].get("ApproximateReceiveCount")) for m in msgs]
        for msg in msgs:
            if token in msg["Body"]:
                return msg
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError(
        f"{what}: {token!r} was not delivered from {url} within {timeout_s}s; last read {last!r}"
    )


def _await_dlq_move(sqs, src_url, dlq_url, *, token, timeout_s, what):
    """Drive and observe the source -> DLQ move; RAISES on the deadline."""
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        for msg in _receive(sqs, src_url, wait_s=1):
            sqs.change_message_visibility(
                QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
        dlq_msgs = _receive(sqs, dlq_url, wait_s=1)
        last = [m["Body"] for m in dlq_msgs]
        for msg in dlq_msgs:
            if token in msg["Body"]:
                return msg
            sqs.change_message_visibility(
                QueueUrl=dlq_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError(
        f"{what}: {token!r} did not reach the DLQ within {timeout_s}s; last DLQ read {last!r}"
    )


def _deliver_up_to_the_count(sqs, src_url, dlq_url, *, token, body, round_name):
    """Receive the message from the source until ApproximateReceiveCount reaches maxReceiveCount;
    the distinct counts, in order of first sight, must run 1..maxReceiveCount while the DLQ holds
    nothing of ours. A duplicate copy that repeats a count adds none."""
    seen: list[int] = []
    while _MAX_RECEIVE_COUNT not in seen:
        msg = _await_delivery(
            sqs,
            src_url,
            token=token,
            timeout_s=30.0,
            what=f"{round_name}: delivery after counts {seen!r}",
        )
        assert msg["Body"] == body, (
            f"{round_name}: a delivery carried {msg['Body']!r}, expected {body!r}"
        )
        n = int(msg["Attributes"]["ApproximateReceiveCount"])
        if n not in seen:
            seen.append(n)
        assert seen == list(range(1, len(seen) + 1)), (
            f"{round_name}: distinct ApproximateReceiveCount values ran {seen!r}, expected 1, 2, ..."
        )
        early = [m for m in _receive(sqs, dlq_url, wait_s=1) if token in m["Body"]]
        assert not early, f"{round_name}: the message reached the DLQ after a count-{n} delivery"
        sqs.change_message_visibility(
            QueueUrl=src_url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
        )


def _await_counts(sqs, url, *, min_visible, in_flight, timeout_s):
    """Bounded poll until at least ``min_visible`` messages are visible and ``in_flight`` are in
    flight; RAISES on the deadline."""
    names = ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=names)["Attributes"]
        last = (attrs.get(names[0]), attrs.get(names[1]))
        if int(last[0] or 0) >= min_visible and last[1] == in_flight:
            return
        time.sleep(2)
    raise AssertionError(
        f"counters on {url} read {last!r} after {timeout_s}s, expected at least {min_visible} "
        f"visible and {in_flight!r} in flight"
    )


def _await_task(sqs, dlq_arn, started, *, timeout_s):
    """Bounded poll of ListMessageMoveTasks until the ``started``-th task (newest first) is listed
    and has left RUNNING; RAISES on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        results = sqs.list_message_move_tasks(SourceArn=dlq_arn, MaxResults=10).get("Results", [])
        last = results[0] if len(results) >= started else None
        if last and last.get("Status") != "RUNNING":
            return last
        time.sleep(3)
    raise AssertionError(
        f"the message move task did not settle within {timeout_s}s; last saw {last!r}"
    )


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A message dead-lettered at maxReceiveCount=2 and moved back with StartMessageMoveTask starts
    over at ApproximateReceiveCount 1 on the source, is withheld from the DLQ for two more
    deliveries, and then dead-letters again with the same body.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_StartMessageMoveTask.html
    """
    sqs = ctx.client("sqs")

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = _queue_arn(sqs, dlq_url)

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-src-"),
        Attributes={
            "VisibilityTimeout": "30",
            "RedrivePolicy": json.dumps(
                {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": _MAX_RECEIVE_COUNT}
            ),
        },
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    token = uuid.uuid4().hex[:8]
    body = f"retry-me-{token}"
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    _deliver_up_to_the_count(
        sqs, src_url, dlq_url, token=token, body=body, round_name="first round"
    )
    first = _await_dlq_move(
        sqs,
        src_url,
        dlq_url,
        token=token,
        timeout_s=_MOVE_S,
        what="after two deliveries the message must move to the DLQ",
    )
    assert first["Body"] == body, f"the first DLQ copy carries {first['Body']!r}, expected {body!r}"
    # Re-expose the DLQ copy so the move task can take it.
    sqs.change_message_visibility(
        QueueUrl=dlq_url, ReceiptHandle=first["ReceiptHandle"], VisibilityTimeout=0
    )
    # The move task sizes itself from the DLQ's counters, so they must show the message visible.
    _await_counts(sqs, dlq_url, min_visible=1, in_flight="0", timeout_s=_COUNTER_S)

    handle = sqs.start_message_move_task(SourceArn=dlq_arn)["TaskHandle"]
    assert isinstance(handle, str) and handle.strip(), (
        f"StartMessageMoveTask returned TaskHandle {handle!r}, expected a non-empty string"
    )
    task = _await_task(sqs, dlq_arn, 1, timeout_s=_TASK_S)
    # The moved-message counter is approximate; the move itself is graded by the source
    # delivering the message again below.
    got = (task.get("Status"), task.get("SourceArn"))
    assert got == ("COMPLETED", dlq_arn), (
        f"the move task settled as (Status, SourceArn) {got!r}, expected ('COMPLETED', <dlq arn>)"
    )
    # A task started without DestinationArn reports none; it moves back to the original source.
    assert "DestinationArn" not in task, (
        f"a task started without DestinationArn lists DestinationArn {task.get('DestinationArn')!r}"
    )

    # Back on the source the message is a fresh message: the count restarts and the policy applies anew.
    _deliver_up_to_the_count(
        sqs, src_url, dlq_url, token=token, body=body, round_name="after redrive"
    )
    second = _await_dlq_move(
        sqs,
        src_url,
        dlq_url,
        token=token,
        timeout_s=_MOVE_S,
        what="after two more deliveries the redriven message must dead-letter again",
    )
    assert second["Body"] == body, (
        f"the second DLQ copy carries {second['Body']!r}, expected {body!r}"
    )
    sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=second["ReceiptHandle"])
    left = [m["Body"] for m in _receive(sqs, src_url, wait_s=2) if token in m["Body"]]
    assert left == [], f"the source still delivers the dead-lettered message {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
