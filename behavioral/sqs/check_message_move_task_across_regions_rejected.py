"""message-move-task-across-regions-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-move-task-across-regions-rejected"
GROUP = "cross-region"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "message-move-task-across-regions-rejected"}
_NOT_FOUND = "ResourceNotFoundException"
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
_MOVE_DEADLINE_S = 180.0


def _other_region(region: str) -> str:
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"]


def _delete_quietly(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NO_SUCH_QUEUE:
            raise


def _dlq_pair(sqs, ctx, base: str) -> tuple[str, str, str]:
    dlq = sqs.create_queue(QueueName=base + "-dlq", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, dlq))
    dlq_arn = _arn(sqs, dlq)
    src = sqs.create_queue(QueueName=base + "-src", tags=_TAGS, Attributes={"RedrivePolicy":
        json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "1"})})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, src))
    return src, dlq, dlq_arn


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """StartMessageMoveTask to a queue in another region is refused (ResourceNotFoundException).

    Nothing moves or is listed; a move from the same DLQ to its home-region source then completes.
    """
    home = ctx.client("sqs")
    alt_region = _other_region(ctx.region)
    alt = ctx.client("sqs", region=alt_region)
    base = ctx.unique_name("sim2real-behav-xr-move-")

    src, dlq, dlq_arn = _dlq_pair(home, ctx, base)
    far_dest = alt.create_queue(QueueName=base + "-dest", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(alt, far_dest))
    far_dest_arn = _arn(alt, far_dest)

    body = ctx.unique_name("parked-")
    home.send_message(QueueUrl=dlq, MessageBody=body)

    err = _error(lambda: home.start_message_move_task(
        SourceArn=dlq_arn, DestinationArn=far_dest_arn))
    assert (err.get("Code"), err.get("Message")) == (
        _NOT_FOUND, "The resource that you specified for the DestinationArn parameter doesn't exist."
    ), f"a move task to a {alt_region!r} destination answered {err!r}"

    tasks = home.list_message_move_tasks(SourceArn=dlq_arn).get("Results", [])
    assert tasks == [], f"the refused move left task(s) listed: {[t.get('Status') for t in tasks]!r}"
    far = alt.receive_message(QueueUrl=far_dest, MaxNumberOfMessages=10, WaitTimeSeconds=3)
    assert far.get("Messages", []) == [], "the refused move delivered into the far queue"

    # Positive control: the same DLQ moves to its home-region source.
    handle = home.start_message_move_task(
        SourceArn=dlq_arn, DestinationArn=_arn(home, src))["TaskHandle"]
    assert handle, "StartMessageMoveTask to the home-region source returned no TaskHandle"
    got: list[str] = []
    deadline = time.monotonic() + _MOVE_DEADLINE_S
    while not got and time.monotonic() < deadline:
        for m in home.receive_message(QueueUrl=src, MaxNumberOfMessages=10,
                                      WaitTimeSeconds=5).get("Messages", []):
            got.append(m["Body"])
            home.delete_message(QueueUrl=src, ReceiptHandle=m["ReceiptHandle"])
    assert got == [body], (
        f"the same-region move delivered {got!r} to the source within {_MOVE_DEADLINE_S}s"
    )
    status = None
    deadline = time.monotonic() + 60
    while status != "COMPLETED" and time.monotonic() < deadline:
        results = home.list_message_move_tasks(SourceArn=dlq_arn).get("Results", [])
        status = results[0]["Status"] if results else None
        if status != "COMPLETED":
            time.sleep(3)
    assert status == "COMPLETED", f"the same-region move task ended as {status!r}"
    far = alt.receive_message(QueueUrl=far_dest, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    assert far.get("Messages", []) == [], "the far queue received a message it was never sent"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
