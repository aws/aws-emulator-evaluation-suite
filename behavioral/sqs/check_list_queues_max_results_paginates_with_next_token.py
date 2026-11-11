"""list-queues-max-results-paginates-with-next-token."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-queues-max-results-paginates-with-next-token"
GROUP = 'state'
SERVICES = ['sqs']

_N = 5
_PAGE = 2
_TAGS = {"sim2real": "list-queues-max-results-paginates-with-next-token"}


def _all_pages(sqs, prefix, page_size):
    """Every page ListQueues returns for ``prefix`` at ``page_size``, following NextToken."""
    pages = []
    kwargs = {"QueueNamePrefix": prefix, "MaxResults": page_size}
    for _ in range(50):
        resp = sqs.list_queues(**kwargs)
        pages.append((resp.get("QueueUrls", []), resp.get("NextToken")))
        token = resp.get("NextToken")
        if not token:
            return pages
        kwargs["NextToken"] = token
    raise AssertionError(f"ListQueues pagination did not terminate after 50 pages: {pages!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListQueues with MaxResults pages a prefix's queues through NextToken.

    Pages hold at most MaxResults, are disjoint, union to the created queues, and end tokenless.
    """
    sqs = ctx.client("sqs")
    prefix = ctx.unique_name("sim2real-behav-lqp-")
    expected = set()
    for i in range(_N):
        url = sqs.create_queue(QueueName=f"{prefix}-{i}", tags=_TAGS)["QueueUrl"]
        ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
        expected.add(url)

    # ListQueues is eventually consistent with CreateQueue: wait until an unpaged listing of the
    # prefix shows every queue before grading the paged walk.
    deadline = time.monotonic() + 90
    while True:
        seen = set(sqs.list_queues(QueueNamePrefix=prefix, MaxResults=1000).get("QueueUrls", []))
        if seen == expected or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert seen == expected, (
        f"an unpaged ListQueues of the prefix never converged on the {_N} created queues: "
        f"{len(seen)} listed, {len(seen & expected)} of them ours"
    )

    pages = _all_pages(sqs, prefix, _PAGE)
    sizes = [len(urls) for urls, _ in pages]
    assert all(s <= _PAGE for s in sizes), (
        f"a ListQueues page exceeded MaxResults={_PAGE}: page sizes {sizes!r}"
    )
    assert len(pages) >= (_N + _PAGE - 1) // _PAGE, (
        f"{_N} queues at MaxResults={_PAGE} need at least {(_N + _PAGE - 1) // _PAGE} pages, "
        f"got {len(pages)} with sizes {sizes!r}"
    )
    assert all(token for _, token in pages[:-1]), (
        f"every page but the last must carry a NextToken; tokens present per page: "
        f"{[bool(t) for _, t in pages]!r}"
    )
    assert pages[-1][1] is None, "the last ListQueues page still carried a NextToken"
    flat = [u for urls, _ in pages for u in urls]
    assert len(flat) == len(set(flat)), (
        f"pagination repeated a queue: {len(flat)} URLs over the pages, {len(set(flat))} distinct"
    )
    assert set(flat) == expected, (
        f"the paged walk returned {len(set(flat))} URLs, {len(set(flat) & expected)} of the "
        f"{_N} created; missing {len(expected - set(flat))}, foreign {len(set(flat) - expected)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
