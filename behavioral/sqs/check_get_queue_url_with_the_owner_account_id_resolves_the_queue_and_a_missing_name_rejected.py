"""get-queue-url-with-the-owner-account-id-resolves-the-queue-and-a-missing-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-queue-url-with-the-owner-account-id-resolves-the-queue-and-a-missing-name-rejected"
GROUP = "queue-identity"
SERVICES = ["sqs"]

_GONE = "AWS.SimpleQueueService.NonExistentQueue"


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetQueueUrl with the caller's own QueueOwnerAWSAccountId returns CreateQueue's usable URL.

    The same lookup is refused with NonExistentQueue for a never-created name and a deleted queue.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-q-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_if_present(sqs, url))

    got = sqs.get_queue_url(QueueName=name, QueueOwnerAWSAccountId=ctx.account)["QueueUrl"]
    assert got == url, f"the owner-qualified lookup returned {got!r}, CreateQueue returned {url!r}"
    sqs.send_message(QueueUrl=got, MessageBody="owner-qualified")
    msgs = sqs.receive_message(QueueUrl=got, WaitTimeSeconds=10).get("Messages", [])
    assert [m["Body"] for m in msgs] == ["owner-qualified"], f"receive via the resolved URL: {msgs!r}"

    missing = ctx.unique_name("sim2real-behav-q-missing-")
    code, message = _error(
        lambda: sqs.get_queue_url(QueueName=missing, QueueOwnerAWSAccountId=ctx.account)
    )
    assert code == _GONE, f"GetQueueUrl for a missing name: got {code}: {message!r}"
    assert message == "The specified queue does not exist.", f"unexpected message {message!r}"

    sqs.delete_queue(QueueUrl=url)
    deadline = time.monotonic() + 90
    while True:  # a deleted queue's name stops resolving within about a minute
        try:
            sqs.get_queue_url(QueueName=name, QueueOwnerAWSAccountId=ctx.account)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            break
        assert time.monotonic() < deadline, "the deleted queue still resolves after 90s"
        time.sleep(3)
    assert code == _GONE, f"GetQueueUrl after DeleteQueue: got {code!r}"


def _delete_if_present(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _GONE:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
