"""client-on-the-queue-url-host-sends-and-receives-on-that-queue."""

from __future__ import annotations

import hashlib
import time
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-on-the-queue-url-host-sends-and-receives-on-that-queue"
GROUP = "lifecycle"
SERVICES = ["sqs"]

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


def _delete_queue(sqs, name: str) -> None:
    """Delete the queue by name; tolerates only not-found."""
    try:
        sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=name)["QueueUrl"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (_NO_SUCH_QUEUE, "QueueDoesNotExist"):
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _receive(ctx, sqs, url: str) -> list[dict]:
    """The first non-empty receive within the poll budget."""
    deadline = time.monotonic() + _budget_s(ctx, 20.0)
    while True:
        got = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", []
        )
        if got:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the run budget ended before the queue delivered")
            return got


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A client on the scheme and host of the QueueUrl CreateQueue returned serves that queue.

    The default client receives what that client sent, and that client receives what it sent.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-message-identifiers.html
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-qurl-")
    ctx.on_cleanup(lambda: _delete_queue(sqs, name))
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    assert not (p := ctx.published_url_mismatch(url)), p
    parts = urlsplit(url)
    on_host = ctx.client("sqs", endpoint_url=f"{parts.scheme}://{parts.netloc}")

    body = f"via-queue-url-host-{name}"
    sent = on_host.send_message(QueueUrl=url, MessageBody=body)
    assert sent["MD5OfMessageBody"] == hashlib.md5(body.encode()).hexdigest(), (
        f"SendMessage on the queue URL host returned MD5OfMessageBody {sent['MD5OfMessageBody']!r}"
    )
    got = _receive(ctx, sqs, url)
    assert [(m["MessageId"], m["Body"]) for m in got] == [(sent["MessageId"], body)], (
        f"the default client must receive the message sent on the queue URL host; got {got!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=got[0]["ReceiptHandle"])

    back = f"via-default-endpoint-{name}"
    back_id = sqs.send_message(QueueUrl=url, MessageBody=back)["MessageId"]
    got = _receive(ctx, on_host, url)
    assert [(m["MessageId"], m["Body"]) for m in got] == [(back_id, back)], (
        f"the client on the queue URL host must receive the message sent to that queue; got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
