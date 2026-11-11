"""queue-name-eighty-character-boundary-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-name-eighty-character-boundary-rejected"
GROUP = "limits"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "queue-name-eighty-character-boundary-rejected"}
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
_STD_MSG = "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length"
_FIFO_MSG = ("The name of a FIFO queue can only include alphanumeric characters, hyphens, or "
             "underscores, must end with .fifo suffix and be 1 to 80 in length.")


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _pad(prefix: str, length: int, fill: str) -> str:
    assert len(prefix) < length, f"prefix {prefix!r} is already {len(prefix)} characters"
    return prefix + fill * (length - len(prefix))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Queue names are at most 80 characters (FIFO including '.fifo'): 80-character names are
    created and resolve; 81 characters, or '.fifo' on a standard queue, is refused with
    InvalidParameterValue and the per-kind message, and no queue is created."""
    sqs = ctx.client("sqs")
    stem = ctx.unique_name("sim2real-behav-name80-")

    std80 = _pad(stem + "-", 80, "s")
    fifo80 = _pad(stem + "-", 75, "f") + ".fifo"
    assert len(std80) == 80 and len(fifo80) == 80, "test names are not 80 characters"

    std_url = sqs.create_queue(QueueName=std80, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=std_url))
    fifo_url = sqs.create_queue(QueueName=fifo80, Attributes={"FifoQueue": "true"}, tags=_TAGS)[
        "QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_url))
    for name, url in ((std80, std_url), (fifo80, fifo_url)):
        assert url.rsplit("/", 1)[-1] == name, (
            f"the URL for an 80-character name ends in {len(url.rsplit('/', 1)[-1])} characters"
        )
        assert sqs.get_queue_url(QueueName=name)["QueueUrl"] == url, (
            "GetQueueUrl for an 80-character name did not resolve to its queue"
        )

    std81 = std80 + "s"
    fifo81 = fifo80[:-5] + "f.fifo"
    std_fifo_suffix = _pad(stem + "-", 70, "s") + ".fifo"
    for name, attrs, msg in (
        (std81, {}, _STD_MSG),
        (fifo81, {"FifoQueue": "true"}, _FIFO_MSG),
        (std_fifo_suffix, {}, _STD_MSG),
    ):
        err = _error(lambda name=name, attrs=attrs: sqs.create_queue(
            QueueName=name, Attributes=attrs, tags=_TAGS))
        assert (err.get("Code"), err.get("Message")) == ("InvalidParameterValue", msg), (
            f"CreateQueue for a {len(name)}-character name (FIFO={bool(attrs)}) answered {err!r}"
        )
        missing = _error(lambda name=name: sqs.get_queue_url(QueueName=name))
        assert missing.get("Code") == _NO_SUCH_QUEUE, (
            f"the refused {len(name)}-character name resolves anyway: {missing!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
