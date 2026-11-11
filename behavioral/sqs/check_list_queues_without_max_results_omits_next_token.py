"""list-queues-without-max-results-omits-next-token."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-queues-without-max-results-omits-next-token"
GROUP = "state"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListQueues pages with a NextToken only when MaxResults is set: with MaxResults=1 two matching
    queues yield a NextToken, and with no MaxResults both urls come back with none.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ListQueues.html
    """
    sqs = ctx.client("sqs")
    prefix = ctx.unique_name("sim2real-behav-lqnt-")
    urls = []
    for suffix in ("-a", "-b"):
        url = sqs.create_queue(QueueName=prefix + suffix, tags={"sim2real": CHECK})["QueueUrl"]
        ctx.on_cleanup(lambda url=url: sqs.delete_queue(QueueUrl=url))
        urls.append(url)

    # ListQueues can lag CreateQueue; poll the unpaged, prefix-filtered listing.
    timeout_s = _budget_s(ctx, 60)
    deadline = time.monotonic() + timeout_s
    resp = sqs.list_queues(QueueNamePrefix=prefix)
    while not set(urls) <= set(resp.get("QueueUrls", [])):
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"ListQueues(prefix={prefix!r}) did not list both {urls!r} within "
                f"{timeout_s:.0f}s; last answer {resp.get('QueueUrls')!r}"
            )
        time.sleep(1)
        resp = sqs.list_queues(QueueNamePrefix=prefix)

    assert sorted(resp["QueueUrls"]) == sorted(urls), (
        f"ListQueues(prefix={prefix!r}) with no MaxResults returned {resp['QueueUrls']!r}, "
        f"expected exactly {sorted(urls)!r}"
    )
    assert "NextToken" not in resp, (
        f"ListQueues with no MaxResults returned a NextToken: {resp.get('NextToken')!r}"
    )

    # Control: the same listing paged one url at a time does return a NextToken.
    paged = sqs.list_queues(QueueNamePrefix=prefix, MaxResults=1)
    assert len(paged.get("QueueUrls", [])) == 1 and paged["QueueUrls"][0] in urls, (
        f"ListQueues(MaxResults=1) returned {paged.get('QueueUrls')!r}, expected one of {urls!r}"
    )
    assert paged.get("NextToken"), (
        f"ListQueues(MaxResults=1) over two matching queues returned no NextToken: {paged!r}"
    )


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
