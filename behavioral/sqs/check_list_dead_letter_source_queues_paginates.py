"""list-dead-letter-source-queues-paginates."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-dead-letter-source-queues-paginates"
GROUP = 'dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real": "list-dead-letter-source-queues-paginates"}
_N = 3


def _walk(sqs, dlq_url, page_size):
    pages = []
    kwargs = {"QueueUrl": dlq_url, "MaxResults": page_size}
    for _ in range(20):
        resp = sqs.list_dead_letter_source_queues(**kwargs)
        pages.append((resp.get("queueUrls", []), resp.get("NextToken")))
        if not resp.get("NextToken"):
            return pages
        kwargs["NextToken"] = resp["NextToken"]
    raise AssertionError(f"ListDeadLetterSourceQueues did not terminate after 20 pages: {pages!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeadLetterSourceQueues with MaxResults=1 pages a DLQ's sources one URL per page.

    Every page but the last has a NextToken; the union is exactly the queues redriving to that DLQ.
    """
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-ldp-")

    def _queue(suffix):
        url = sqs.create_queue(QueueName=f"{base}-{suffix}", tags=_TAGS)["QueueUrl"]
        ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
        arn = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        return url, arn

    dlq_url, dlq_arn = _queue("dlq")
    other_dlq_url, other_dlq_arn = _queue("dlq2")
    expected = set()
    for i in range(_N):
        url, _ = _queue(f"s{i}")
        sqs.set_queue_attributes(QueueUrl=url, Attributes={"RedrivePolicy": json.dumps(
            {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 4})})
        expected.add(url)
    foreign_url, _ = _queue("foreign")
    sqs.set_queue_attributes(QueueUrl=foreign_url, Attributes={"RedrivePolicy": json.dumps(
        {"deadLetterTargetArn": other_dlq_arn, "maxReceiveCount": 4})})

    # The source listing is eventually consistent with SetQueueAttributes(RedrivePolicy).
    deadline = time.monotonic() + 90
    while True:
        seen = set(sqs.list_dead_letter_source_queues(
            QueueUrl=dlq_url, MaxResults=1000).get("queueUrls", []))
        if seen == expected or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert seen == expected, (
        f"an unpaged listing never converged on the {_N} sources: {len(seen)} listed, "
        f"{len(seen & expected)} of them expected, foreign queue "
        f"{'present' if foreign_url in seen else 'absent'}"
    )

    pages = _walk(sqs, dlq_url, 1)
    sizes = [len(u) for u, _ in pages]
    assert sizes == [1] * _N, f"MaxResults=1 over {_N} sources gave page sizes {sizes!r}"
    assert all(t for _, t in pages[:-1]) and pages[-1][1] is None, (
        f"NextToken presence per page was {[bool(t) for _, t in pages]!r}; every page but the "
        f"last must carry one"
    )
    flat = [u for urls, _ in pages for u in urls]
    assert len(set(flat)) == len(flat) and set(flat) == expected, (
        f"the paged walk returned {len(flat)} URLs ({len(set(flat))} distinct), "
        f"{len(set(flat) & expected)} of the {_N} expected sources"
    )

    other = sqs.list_dead_letter_source_queues(QueueUrl=other_dlq_url).get("queueUrls", [])
    deadline = time.monotonic() + 60
    while other != [foreign_url] and time.monotonic() < deadline:
        time.sleep(2)
        other = sqs.list_dead_letter_source_queues(QueueUrl=other_dlq_url).get("queueUrls", [])
    assert other == [foreign_url], (
        f"the second DLQ lists {len(other)} sources, expected only the one queue redriving to it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
