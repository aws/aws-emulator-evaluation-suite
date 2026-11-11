"""queue-name-resolution-is-case-sensitive-and-exact."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-name-resolution-is-case-sensitive-and-exact"
GROUP = "queue-identity"
SERVICES = ["sqs"]

_GONE = "AWS.SimpleQueueService.NonExistentQueue"
_GONE_MESSAGE = "The specified queue does not exist."
_TAGS = {"sim2real": "queue-name-resolution-is-case-sensitive-and-exact"}


def _error(fn):
    """The botocore (Code, Message) ``fn()`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _list_urls(sqs, prefix):
    urls, token = [], None
    while True:
        page = sqs.list_queues(QueueNamePrefix=prefix, **({"NextToken": token} if token else {}))
        urls.extend(page.get("QueueUrls", []))
        token = page.get("NextToken")
        if not token:
            return urls


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Queue names resolve exactly: GetQueueUrl and ListQueues miss a different-case spelling, a FIFO
    name without its .fifo suffix, and a .FIFO suffix, each refused with NonExistentQueue.
    """
    sqs = ctx.client("sqs")

    name = ctx.unique_name("sim2real-behav-Case-")
    url = sqs.create_queue(QueueName=name, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Positive control: the exact name resolves, via both operations.
    resolved = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    assert resolved == url, f"GetQueueUrl({name!r}) returned {resolved!r}, CreateQueue returned {url!r}"
    deadline = time.monotonic() + 30
    while True:
        urls = _list_urls(sqs, name)
        if url in urls:
            break
        assert time.monotonic() < deadline, f"ListQueues(prefix={name!r}) never listed {url!r}"
        time.sleep(1)

    # A different-case spelling of the exact same name is a MISS on both operations.
    flipped = name.swapcase()
    assert flipped != name, f"swapcase() of {name!r} produced the same string, test is void"
    code, msg = _error(lambda: sqs.get_queue_url(QueueName=flipped))
    assert code == _GONE, f"GetQueueUrl({flipped!r}) (case-flipped) gave {code!r}, expected {_GONE!r}"
    assert msg == _GONE_MESSAGE, (
        f"GetQueueUrl({flipped!r}) (case-flipped) gave message {msg!r}, expected {_GONE_MESSAGE!r}"
    )
    other_case_urls = _list_urls(sqs, flipped)
    assert url not in other_case_urls, (
        f"ListQueues(prefix={flipped!r}) (case-flipped) matched {url!r}, "
        f"which was created under the different-case name {name!r}"
    )

    # A FIFO queue's base name, with the mandatory .fifo suffix dropped, is also a MISS.
    fifo_base = ctx.unique_name("sim2real-behav-fifobase-")
    fifo_name = fifo_base + ".fifo"
    fifo_url = sqs.create_queue(
        QueueName=fifo_name, Attributes={"FifoQueue": "true"}, tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_url))

    resolved_fifo = sqs.get_queue_url(QueueName=fifo_name)["QueueUrl"]
    assert resolved_fifo == fifo_url, (
        f"GetQueueUrl({fifo_name!r}) returned {resolved_fifo!r}, CreateQueue returned {fifo_url!r}"
    )
    code, msg = _error(lambda: sqs.get_queue_url(QueueName=fifo_base))
    assert code == _GONE, (
        f"GetQueueUrl({fifo_base!r}) (suffix dropped) gave {code!r}, expected {_GONE!r}"
    )
    assert msg == _GONE_MESSAGE, (
        f"GetQueueUrl({fifo_base!r}) (suffix dropped) gave message {msg!r}, "
        f"expected {_GONE_MESSAGE!r}"
    )

    # The suffix itself is matched case-sensitively too: ``.FIFO`` is not ``.fifo``.
    upper_suffix = fifo_base + ".FIFO"
    code, msg = _error(lambda: sqs.get_queue_url(QueueName=upper_suffix))
    assert code == _GONE, (
        f"GetQueueUrl({upper_suffix!r}) (suffix upper-cased) gave {code!r}, expected {_GONE!r}"
    )
    assert msg == _GONE_MESSAGE, (
        f"GetQueueUrl({upper_suffix!r}) (suffix upper-cased) gave message {msg!r}, "
        f"expected {_GONE_MESSAGE!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
