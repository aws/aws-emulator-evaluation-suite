"""queue-url-from-another-region-not-served-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-url-from-another-region-not-served-rejected"
GROUP = "cross-region"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "queue-url-from-another-region-not-served-rejected"}
_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
_NO_SUCH_QUEUE_MSG = "The specified queue does not exist."


def _other_region(region: str) -> str:
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A home-region client handed another region's QueueUrl gets NonExistentQueue on SendMessage,
    ReceiveMessage, GetQueueAttributes and GetQueueUrl, and nothing reaches the far queue, because
    a queue is served only by its own region's endpoint."""
    home = ctx.client("sqs")
    alt_region = _other_region(ctx.region)
    alt = ctx.client("sqs", region=alt_region)
    name = ctx.unique_name("sim2real-behav-xr-url-")
    far_url = alt.create_queue(QueueName=name, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: alt.delete_queue(QueueUrl=far_url))
    # An emulator's own endpoint-relative URL carries no region (graded by scheme only).
    assert (
        alt_region in far_url
        or ctx.published_url_mismatch(far_url, labels=(alt_region,)) is None
    ), f"the {alt_region!r} queue URL does not name its region"

    refused_body = ctx.unique_name("refused-")
    for label, fn in (
        ("SendMessage", lambda: home.send_message(QueueUrl=far_url, MessageBody=refused_body)),
        ("ReceiveMessage", lambda: home.receive_message(QueueUrl=far_url)),
        ("GetQueueAttributes",
         lambda: home.get_queue_attributes(QueueUrl=far_url, AttributeNames=["QueueArn"])),
        ("GetQueueUrl", lambda: home.get_queue_url(QueueName=name)),
    ):
        err = _error(fn)
        assert (err.get("Code"), err.get("Message")) == (_NO_SUCH_QUEUE, _NO_SUCH_QUEUE_MSG), (
            f"{label} on the {ctx.region!r} endpoint for a {alt_region!r} queue answered {err!r}"
        )

    # Positive control and effect-absent: the far queue's own endpoint serves it, and it holds
    # only the message sent there.
    own_body = ctx.unique_name("own-")
    alt.send_message(QueueUrl=far_url, MessageBody=own_body)
    bodies: list[str] = []
    deadline = time.monotonic() + 30
    while own_body not in bodies and time.monotonic() < deadline:
        for m in alt.receive_message(QueueUrl=far_url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=3).get("Messages", []):
            bodies.append(m["Body"])
            alt.delete_message(QueueUrl=far_url, ReceiptHandle=m["ReceiptHandle"])
    for m in alt.receive_message(QueueUrl=far_url, MaxNumberOfMessages=10,
                                 WaitTimeSeconds=3).get("Messages", []):
        bodies.append(m["Body"])
    assert bodies == [own_body], (
        f"the {alt_region!r} queue delivered {bodies!r}; expected only the message sent through "
        f"its own endpoint, and never the one the {ctx.region!r} endpoint refused"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
