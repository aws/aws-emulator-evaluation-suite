"""list-subscriptions-by-topic-pagination-exactness."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "list-subscriptions-by-topic-pagination-exactness"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']

_SUBSCRIPTION_COUNT = 105   # > the 100-item SNS list page size, so >= 2 pages are required



def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic (tagged) and register DeleteTopic cleanup; returns the TopicArn. DeleteTopic
    removes every subscription on the topic, so it is the only teardown the subscriptions need."""
    arn = client.create_topic(
        Name=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
        **({"Attributes": attributes} if attributes else {}),
    )["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn


def _fake_queue_arn(topic_arn, name=None):
    """A well-formed SQS queue ARN in the topic's account/region (SNS confirms sqs
    subscriptions without verifying the queue exists, keeping this single-service and
    making 105 subscribers free to create)."""
    parts = topic_arn.split(":")
    name = name or f"sim2real-behav-sns-q-{uuid.uuid4().hex[:8]}"
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred(val); raise AssertionError on deadline miss (never a bare sleep)."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: condition not met within {timeout_s}s, last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _pages(client, topic_arn, *, max_pages=20):
    """Walk ListSubscriptionsByTopic with NextToken; return the list of per-page ARN lists."""
    pages = []
    token = None
    for _ in range(max_pages):
        kwargs = {"TopicArn": topic_arn}
        if token:
            kwargs["NextToken"] = token
        resp = client.list_subscriptions_by_topic(**kwargs)
        pages.append([s["SubscriptionArn"] for s in resp["Subscriptions"]])
        token = resp.get("NextToken")
        if not token:
            return pages
    raise AssertionError(
        f"ListSubscriptionsByTopic still returned a NextToken after {max_pages} pages -- "
        "the token is not advancing"
    )


def _err(fn):
    """Call fn(); return the (Code, Message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")




@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """NextToken paging over 105 subscriptions is exact (>= 2 pages, no duplicates, omissions or
    overlap, no trailing token) and a garbage NextToken is refused with InvalidParameter.
    Page order and page size are not asserted: SNS documents neither.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-paging-"))

    created = set()
    for i in range(_SUBSCRIPTION_COUNT):
        endpoint = _fake_queue_arn(topic_arn, f"sim2real-behav-sns-paging-q-{i:03d}-{uuid.uuid4().hex[:8]}")
        arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=endpoint)["SubscriptionArn"]
        assert arn and arn != "pending confirmation", (
            f"expected subscription {i} to auto-confirm, got {arn!r}"
        )
        created.add(arn)
    assert len(created) == _SUBSCRIPTION_COUNT, (
        f"expected {_SUBSCRIPTION_COUNT} distinct SubscriptionArns, got {len(created)}"
    )

    pages = _poll(
        lambda: _pages(sns, topic_arn),
        lambda p: sum(len(x) for x in p) >= _SUBSCRIPTION_COUNT,
        timeout_s=60.0,
        interval_s=3.0,
        what=f"all {_SUBSCRIPTION_COUNT} subscriptions become visible across pages",
    )

    assert len(pages) >= 2, (
        f"{_SUBSCRIPTION_COUNT} subscriptions must not fit in one page; got {len(pages)} page(s) "
        f"of sizes {[len(p) for p in pages]}"
    )

    flat = [a for page in pages for a in page]
    assert len(flat) == _SUBSCRIPTION_COUNT, (
        "paging must return each subscription exactly once; expected "
        f"{_SUBSCRIPTION_COUNT} rows across {len(pages)} pages, got {len(flat)} "
        f"(page sizes {[len(p) for p in pages]})"
    )
    assert len(set(flat)) == len(flat), (
        "paging returned a duplicated SubscriptionArn: "
        f"{sorted(a for a in set(flat) if flat.count(a) > 1)[:5]}"
    )
    assert set(flat) == created, (
        "the union of all pages must be exactly the created set; "
        f"missing {sorted(created - set(flat))[:5]}, unexpected {sorted(set(flat) - created)[:5]}"
    )
    for i in range(len(pages) - 1):
        overlap = set(pages[i]) & set(pages[i + 1])
        assert not overlap, (
            f"page {i} and page {i + 1} must be disjoint; overlapping {sorted(overlap)[:5]}"
        )

    # The final page must not carry a NextToken -- _pages() terminated only because it did
    # not, so re-assert the boundary explicitly against the last request.
    last_token = None
    token = None
    for _ in range(len(pages)):
        kwargs = {"TopicArn": topic_arn}
        if token:
            kwargs["NextToken"] = token
        resp = sns.list_subscriptions_by_topic(**kwargs)
        last_token = resp.get("NextToken")
        token = last_token
    assert last_token is None, (
        f"the final page must omit NextToken, got {last_token!r}"
    )

    # Break exactly one thing: a NextToken that was never issued.
    code, message = _err(lambda: sns.list_subscriptions_by_topic(
        TopicArn=topic_arn, NextToken="sim2real-behav-not-a-real-token"
    ))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a NextToken that was never issued, got {code}"
    )
    assert message == "Invalid parameter: NextToken", (
        f"expected the exact InvalidParameter message AWS returns, got {message!r}"
    )

    # The un-tokened first page holds the same ARNs as before, so the
    # rejected call did not consume, invalidate, or advance any server-side cursor.
    first_again = [s["SubscriptionArn"] for s in
                   sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]]
    assert set(first_again) == set(pages[0]), (
        "a rejected NextToken must not disturb the unpaginated listing; expected the same "
        f"{len(pages[0])} ARNs, got {len(first_again)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
