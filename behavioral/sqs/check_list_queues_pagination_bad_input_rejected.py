"""list-queues-pagination-bad-input-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-queues-pagination-bad-input-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

_TAGS = {"sim2real": "list-queues-pagination-bad-input-rejected"}
MSG_MAX = "Value for parameter MaxResults is invalid. Reason: MaxResults must be an integer between 1 and 1000."
MSG_TOKEN = "Invalid or expired next token."


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListQueues refuses MaxResults=1001 and a forged NextToken with InvalidParameterValue and exact
    messages, while MaxResults=1000 over the same prefix lists exactly the created queue."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-lqbad-")
    url = sqs.create_queue(QueueName=name, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    code, msg = _err(lambda: sqs.list_queues(QueueNamePrefix=name, MaxResults=1001))
    assert code == "InvalidParameterValue", f"MaxResults=1001 gave code {code!r}"
    assert msg == MSG_MAX, f"MaxResults=1001 gave message {msg!r}"

    code, msg = _err(lambda: sqs.list_queues(
        QueueNamePrefix=name, MaxResults=5, NextToken="sim2real-not-a-token"))
    assert code == "InvalidParameterValue", f"a forged NextToken gave code {code!r}"
    assert msg == MSG_TOKEN, f"a forged NextToken gave message {msg!r}"

    deadline = time.monotonic() + 60
    while True:
        resp = sqs.list_queues(QueueNamePrefix=name, MaxResults=1000)
        urls = resp.get("QueueUrls", [])
        if urls or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert urls == [url], (
        f"positive control: ListQueues(prefix, MaxResults=1000) returned {len(urls)} URLs, "
        f"expected exactly the one created queue"
    )
    assert "NextToken" not in resp, "a one-queue listing at MaxResults=1000 carried a NextToken"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
