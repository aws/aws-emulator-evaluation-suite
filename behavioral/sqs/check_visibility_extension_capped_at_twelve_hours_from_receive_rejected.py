"""visibility-extension-capped-at-twelve-hours-from-receive-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "visibility-extension-capped-at-twelve-hours-from-receive-rejected"
GROUP = 'visibility'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "vt-twelve-hour-cap"}

_MAX_S = 43200
_CAP_MESSAGE = (
    f"Value {_MAX_S} for parameter VisibilityTimeout is invalid. Reason: Total VisibilityTimeout "
    f"for the message is beyond the limit [{_MAX_S} seconds]."
)


def _receive_all(sqs, url, n, vt):
    got: list[dict] = []
    deadline = time.monotonic() + 30
    while len(got) < n and time.monotonic() < deadline:
        got += sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, VisibilityTimeout=vt,
        ).get("Messages", [])
    return got


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """ChangeMessageVisibility cannot push visibility past 12 hours from receive: 43200s soon after
    a receive is refused though in range, a shorter extension is accepted, and in the batch form the
    over-cap entry fails alone."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    bodies = [f"cap-{i}-{token}" for i in range(3)]
    for b in bodies:
        sqs.send_message(QueueUrl=url, MessageBody=b)
    # Received under the full 12-hour timeout, so any further extension crosses the cap.
    got = _receive_all(sqs, url, 3, _MAX_S)
    assert sorted(m["Body"] for m in got) == sorted(bodies), (
        f"expected to receive {sorted(bodies)!r}, got {sorted(m['Body'] for m in got)!r}")
    handle = {m["Body"]: m["ReceiptHandle"] for m in got}
    # The cap is counted from the receive: retry until a measurable instant has passed and the
    # 43200 s extension crosses it. An accepted try only re-arms the same 12 h-from-receive cap.
    code = msg = None
    left = ctx.time_left()
    cap_deadline = time.monotonic() + (10 if left is None else min(10, left))
    deadline = cap_deadline
    while time.monotonic() < deadline:
        try:
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=handle[bodies[0]], VisibilityTimeout=_MAX_S)
        except ClientError as exc:
            code, msg = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
            break
        time.sleep(1)
    assert (code, msg) == ("InvalidParameterValue", _CAP_MESSAGE), (
        f"extending past 12h from receive gave {(code, msg)!r}")

    # Positive control: an extension that stays under the cap is accepted.
    sqs.change_message_visibility(
        QueueUrl=url, ReceiptHandle=handle[bodies[0]], VisibilityTimeout=_MAX_S - 600)

    # Same cap clock for the batch: retry until its over-cap entry is refused.
    while True:
        resp = sqs.change_message_visibility_batch(QueueUrl=url, Entries=[
            {"Id": "over", "ReceiptHandle": handle[bodies[1]], "VisibilityTimeout": _MAX_S},
            {"Id": "release", "ReceiptHandle": handle[bodies[2]], "VisibilityTimeout": 0},
        ])
        if any(e["Id"] == "over" for e in resp.get("Failed", [])) or time.monotonic() >= cap_deadline:
            break
        time.sleep(1)
    ok = [e["Id"] for e in resp.get("Successful", [])]
    failed = {e["Id"]: (e.get("Code"), e.get("SenderFault"), e.get("Message"))
              for e in resp.get("Failed", [])}
    assert ok == ["release"], f"batch Successful ids {ok!r}, expected ['release']"
    assert failed == {"over": ("InvalidParameterValue", True, _CAP_MESSAGE)}, (
        f"batch Failed entries {failed!r}")

    # The applied entry really re-exposed its message; the refused ones stay hidden.
    seen: list[str] = []
    deadline = time.monotonic() + 30
    while bodies[2] not in seen and time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=2).get("Messages", []):
            seen.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert seen == [bodies[2]], (
        f"only the message released by the batch's VisibilityTimeout=0 entry may be "
        f"receivable; got {seen!r}, expected {[bodies[2]]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
