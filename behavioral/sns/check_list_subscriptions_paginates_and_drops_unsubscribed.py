"""list-subscriptions-paginates-and-drops-unsubscribed."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-subscriptions-paginates-and-drops-unsubscribed"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']

_N_SUBS = 105  # more than one ListSubscriptions page (SNS pages at 100 subscriptions)
_PAGE_MAX = 100


def _walk(sns, max_pages=2000):
    """Walk account-wide ListSubscriptions by hand; return the list of per-page entry lists."""
    pages, token = [], None
    for _ in range(max_pages):
        kwargs = {"NextToken": token} if token else {}
        resp = sns.list_subscriptions(**kwargs)
        pages.append(resp.get("Subscriptions", []))
        token = resp.get("NextToken")
        if not token:
            return pages
    raise AssertionError(f"ListSubscriptions still returned a NextToken after {max_pages} pages")


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
    """Account-wide ListSubscriptions pages at most 100 entries, a NextToken walk returns each
    of 105 new subscriptions exactly once with its Owner, Protocol, Endpoint and TopicArn,
    and an unsubscribed one leaves the listing while its siblings stay.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-lspage-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    region, account = topic_arn.split(":")[3], topic_arn.split(":")[4]
    qprefix = ctx.unique_name("sim2real-behav-sns-lspage-q-")

    endpoints = {}
    for i in range(_N_SUBS):
        endpoint = f"arn:aws:sqs:{region}:{account}:{qprefix}-{i:03d}"
        sub_arn = sns.subscribe(
            TopicArn=topic_arn, Protocol="sqs", Endpoint=endpoint, ReturnSubscriptionArn=True,
        )["SubscriptionArn"]
        ctx.on_cleanup(lambda s=sub_arn: sns.unsubscribe(SubscriptionArn=s))
        endpoints[sub_arn] = endpoint
    assert len(endpoints) == _N_SUBS, f"expected {_N_SUBS} distinct SubscriptionArns, got {len(endpoints)}"

    mine = set(endpoints)

    def _each_once(ps, wanted):
        # A walk that overlaps another writer's Subscribe or Unsubscribe may shift page
        # boundaries; a walk is graded once it lists exactly the wanted members of `mine`, each once.
        arns = [e["SubscriptionArn"] for p in ps for e in p if e["SubscriptionArn"] in mine]
        return len(arns) == len(set(arns)) and set(arns) == wanted

    pages = _poll(
        lambda: _walk(sns),
        lambda ps: _each_once(ps, mine),
        timeout_s=90.0, interval_s=3.0,
        what="every created subscription appears in a full ListSubscriptions walk",
    )
    oversized = [len(p) for p in pages if len(p) > _PAGE_MAX]
    assert not oversized, f"ListSubscriptions returned pages larger than {_PAGE_MAX}: sizes {oversized!r}"
    assert len(pages) >= 2, (
        f"the account holds at least {_N_SUBS} subscriptions, so ListSubscriptions must "
        f"paginate; got {len(pages)} page(s)"
    )
    entries = [e for p in pages for e in p if e["SubscriptionArn"] in mine]
    assert len(entries) == _N_SUBS, (
        f"a full walk must return each of the {_N_SUBS} subscriptions exactly once, "
        f"saw {len(entries)} occurrences"
    )
    wrong = [e for e in entries if (
        e.get("TopicArn") != topic_arn or e.get("Protocol") != "sqs"
        or e.get("Owner") != ctx.account or e.get("Endpoint") != endpoints[e["SubscriptionArn"]]
    )]
    assert not wrong, (
        f"{len(wrong)} listed subscription(s) carry the wrong TopicArn/Protocol/Owner/Endpoint; "
        f"first fields: {sorted(wrong[0]) if wrong else None!r}"
    )

    gone = next(iter(sorted(mine)))
    sns.unsubscribe(SubscriptionArn=gone)
    after = _poll(
        lambda: _walk(sns),
        lambda ps: _each_once(ps, mine - {gone}),
        timeout_s=90.0, interval_s=3.0,
        what="the unsubscribed subscription leaves account-wide ListSubscriptions",
    )
    remaining = {e["SubscriptionArn"] for p in after for e in p} & mine
    assert remaining == mine - {gone}, (
        f"unsubscribing one subscription must leave its {_N_SUBS - 1} siblings listed, "
        f"{len(remaining)} remain"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
