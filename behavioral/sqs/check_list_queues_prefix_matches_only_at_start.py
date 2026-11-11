"""list-queues-prefix-matches-only-at-start."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-queues-prefix-matches-only-at-start"
GROUP = "state"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "list-queues-prefix-matches-only-at-start"}


def _list_urls(sqs, prefix):
    urls, token = [], None
    while True:
        page = sqs.list_queues(QueueNamePrefix=prefix, **({"NextToken": token} if token else {}))
        urls.extend(page.get("QueueUrls", []))
        token = page.get("NextToken")
        if not token:
            return urls


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListQueues(QueueNamePrefix) matches only at the start of the name: a queue whose name merely
    contains the prefix string is excluded, while one whose name starts with it is included."""
    sqs = ctx.client("sqs")
    token = ctx.unique_name("sim2real-behav-anchor-")

    # Starts with the token: must match.
    starts_name = token + "-head"
    starts_url = sqs.create_queue(QueueName=starts_name, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=starts_url))

    # Contains the token, but does not start with it: must NOT match.
    mid_name = ctx.unique_name("sim2real-behav-pre-") + "-" + token
    mid_url = sqs.create_queue(QueueName=mid_name, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=mid_url))

    deadline = time.monotonic() + 30
    while True:
        urls = _list_urls(sqs, token)
        if starts_url in urls:
            break
        assert time.monotonic() < deadline, (
            f"ListQueues(prefix={token!r}) never returned the prefix-matching queue {starts_url!r}"
        )
        time.sleep(1)

    assert mid_url not in urls, (
        f"ListQueues(prefix={token!r}) returned {mid_url!r}, whose name {mid_name!r} contains "
        f"the filter but does not start with it — the filter is matching as a substring, not a prefix"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
