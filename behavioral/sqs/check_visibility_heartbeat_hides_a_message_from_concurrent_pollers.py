"""visibility-heartbeat-hides-a-message-from-concurrent-pollers."""
from __future__ import annotations

import concurrent.futures
import threading
import time

from behavioral_harness import tags

CHECK = "visibility-heartbeat-hides-a-message-from-concurrent-pollers"
GROUP = "concurrency"
SERVICES = ["sqs"]

_WINDOW_S = 10
_HEARTBEAT_EVERY_S = 2.0
# The hold spans more than two windows, so the unheartbeated sibling lapses well inside it.
_HOLD_S = 24.0
# The after-watch outlasts one full window past the last extension, so an undeleted message
# would have reappeared within it.
_AFTER_S = 12.0
_POLLERS = 3
_TAGS = {"sim2real": "visibility-heartbeat-hides-a-message-from-concurrent-pollers"}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Heartbeating ChangeMessageVisibility keeps a message from concurrent long-pollers while an
    unheartbeated sibling is handed out once its window lapses; the original receipt handle still
    deletes the heartbeated message afterwards and it never reappears."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-heartbeat-"),
        Attributes={"VisibilityTimeout": str(_WINDOW_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    kept_body = ctx.unique_name("kept-")
    dropped_body = ctx.unique_name("dropped-")
    sqs.send_message(QueueUrl=url, MessageBody=kept_body)
    sqs.send_message(QueueUrl=url, MessageBody=dropped_body)

    handles: dict[str, str] = {}
    deadline = time.monotonic() + 30
    while len(handles) < 2 and time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", []):
            handles[m["Body"]] = m["ReceiptHandle"]
    assert set(handles) == {kept_body, dropped_body}, (
        f"the worker could not take both messages before heartbeating: holds {sorted(handles)!r}"
    )
    kept_handle = handles[kept_body]

    stop = threading.Event()
    lock = threading.Lock()
    polled: list[str] = []
    heartbeat_errors: list[str] = []

    def heartbeat() -> None:
        end = time.monotonic() + _HOLD_S
        while time.monotonic() < end:
            try:
                sqs.change_message_visibility(
                    QueueUrl=url, ReceiptHandle=kept_handle, VisibilityTimeout=_WINDOW_S
                )
            except Exception as exc:  # asserted below
                heartbeat_errors.append(repr(exc))
                return
            time.sleep(_HEARTBEAT_EVERY_S)

    def poller(_: int) -> None:
        while not stop.is_set():
            for m in sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, VisibilityTimeout=60
            ).get("Messages", []):
                with lock:
                    polled.append(m["Body"])
                if m["Body"] == dropped_body:
                    sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=_POLLERS + 1) as ex:
        pollers = [ex.submit(poller, i) for i in range(_POLLERS)]
        ex.submit(heartbeat).result()
        stop.set()
        for f in pollers:
            f.result()

    assert heartbeat_errors == [], f"a heartbeat extension was refused: {heartbeat_errors!r}"
    assert kept_body not in polled, (
        f"a concurrent poller received the heartbeated message {polled.count(kept_body)} time(s) "
        f"while its owner kept extending a {_WINDOW_S}s window every {_HEARTBEAT_EVERY_S}s"
    )
    assert polled.count(dropped_body) >= 1, (
        f"the message whose {_WINDOW_S}s window was left to lapse never reached any of "
        f"{_POLLERS} pollers in {_HOLD_S}s; pollers saw {polled!r}"
    )

    sqs.delete_message(QueueUrl=url, ReceiptHandle=kept_handle)
    after: list[str] = []
    end = time.monotonic() + _AFTER_S
    while time.monotonic() < end:
        after.extend(m["Body"] for m in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []))
    assert kept_body not in after, (
        "the original receipt handle, used after repeated extensions, did not delete the message: "
        "it was received again"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
