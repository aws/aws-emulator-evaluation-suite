"""list-topics-paginates-every-created-topic-exactly-once."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-topics-paginates-every-created-topic-exactly-once"
GROUP = 'topic-lifecycle'
SERVICES = ['sns']

_N_TOPICS = 105  # more than one ListTopics page (SNS pages at 100 topics)
_PAGE_MAX = 100


def _walk(sns, max_pages=500):
    """Walk ListTopics by hand with NextToken; return the list of per-page TopicArn lists."""
    pages, token = [], None
    for _ in range(max_pages):
        kwargs = {"NextToken": token} if token else {}
        resp = sns.list_topics(**kwargs)
        pages.append([t["TopicArn"] for t in resp.get("Topics", [])])
        token = resp.get("NextToken")
        if not token:
            return pages
    raise AssertionError(f"ListTopics still returned a NextToken after {max_pages} pages")


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred(val); raise AssertionError on deadline miss (never a bare sleep)."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: condition not met within {timeout_s}s")
        time.sleep(interval_s)
        val = fn()
    return val


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTopics pages at most 100 topics per response and a NextToken walk returns every
    one of 105 freshly created topics exactly once.
    """
    sns = ctx.client("sns")
    prefix = ctx.unique_name("sim2real-behav-sns-ltpage-")
    tags_kv = [{"Key": "sim2real", "Value": CHECK}]
    created = []
    for i in range(_N_TOPICS):
        arn = sns.create_topic(Name=f"{prefix}-{i:03d}", Tags=tags_kv)["TopicArn"]
        ctx.on_cleanup(lambda arn=arn: sns.delete_topic(TopicArn=arn))
        created.append(arn)
    assert len(set(created)) == _N_TOPICS, (
        f"{_N_TOPICS} distinct names must yield {_N_TOPICS} distinct TopicArns, got {len(set(created))}"
    )

    mine = set(created)

    def _consistent(ps):
        # A walk that overlaps another writer's CreateTopic or DeleteTopic may shift page
        # boundaries; a walk is graded once it lists each created topic exactly once and
        # page 2 does not repeat page 1's last topic.
        seen = [a for p in ps for a in p if a in mine]
        resumes = len(ps) < 2 or not (ps[0] and ps[1]) or ps[0][-1] != ps[1][0]
        return len(seen) == len(set(seen)) and set(seen) == mine and resumes

    pages = _poll(
        lambda: _walk(sns),
        _consistent,
        timeout_s=60.0, interval_s=3.0,
        what="every created topic appears in a full ListTopics walk",
    )

    oversized = [len(p) for p in pages if len(p) > _PAGE_MAX]
    assert not oversized, f"ListTopics returned pages larger than {_PAGE_MAX} topics: sizes {oversized!r}"
    assert len(pages) >= 2, (
        f"the account holds at least {_N_TOPICS} topics, so ListTopics must paginate; "
        f"got {len(pages)} page(s)"
    )
    flat = [a for p in pages for a in p]
    seen_mine = [a for a in flat if a in mine]
    dupes = sorted({a for a in seen_mine if seen_mine.count(a) > 1})
    assert not dupes, f"{len(dupes)} created topic(s) appeared on more than one page of one walk"
    assert len(seen_mine) == _N_TOPICS, (
        f"a full walk must return each of the {_N_TOPICS} created topics exactly once, "
        f"saw {len(seen_mine)} occurrences"
    )
    # A page's NextToken resumes after that page: the first page's last topic is never the
    # second page's first.
    assert pages[0] and pages[1] and pages[0][-1] != pages[1][0], (
        "page 2 must resume after page 1, not repeat its last topic"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
