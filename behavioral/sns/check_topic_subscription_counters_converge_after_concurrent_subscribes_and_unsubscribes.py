"""topic-subscription-counters-converge-after-concurrent-subscribes-and-unsubscribes."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-subscription-counters-converge-after-concurrent-subscribes-and-unsubscribes"
GROUP = "topic-lifecycle"
SERVICES = ["sns"]

_CONFIRMED = 16
_PENDING = 4
_REMOVED = 10


def _counters(sns, topic: str) -> tuple[int, int]:
    attrs = sns.get_topic_attributes(TopicArn=topic)["Attributes"]
    return int(attrs["SubscriptionsConfirmed"]), int(attrs["SubscriptionsPending"])


def _converge(sns, topic: str, want: tuple[int, int], what: str) -> None:
    deadline = time.monotonic() + 120
    seen = _counters(sns, topic)
    while seen != want:
        assert time.monotonic() < deadline, (
            f"{what}: (SubscriptionsConfirmed, SubscriptionsPending) never reached {want}; last {seen}")
        time.sleep(3)
        seen = _counters(sns, topic)


def _listed(sns, topic: str) -> list[dict]:
    return [s for p in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic)
            for s in p["Subscriptions"]]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Twenty concurrent subscribes (16 auto-confirming sqs, 4 pending email) converge the topic's
    SubscriptionsConfirmed/SubscriptionsPending counters to 16/4, matching the listing; ten
    concurrent unsubscribes of confirmed ones bring them to 6/4 and the listing to the survivors.
    """
    sns = ctx.client("sns")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-ctrs-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    region, account = topic.split(":")[3], topic.split(":")[4]
    tag = uuid.uuid4().hex[:8]
    queues = [f"arn:aws:sqs:{region}:{account}:sim2real-behav-sns-ctrs-{tag}-{i}" for i in range(_CONFIRMED)]
    mails = [f"sim2real-behav-sns-{tag}-{i}@example.com" for i in range(_PENDING)]

    def subscribe(target: tuple[str, str]) -> str:
        protocol, endpoint = target
        return sns.subscribe(TopicArn=topic, Protocol=protocol, Endpoint=endpoint,
                             ReturnSubscriptionArn=True)["SubscriptionArn"]

    targets = [("sqs", q) for q in queues] + [("email", m) for m in mails]
    with ThreadPoolExecutor(max_workers=len(targets)) as pool:
        arns = list(pool.map(subscribe, targets))
    confirmed = arns[:_CONFIRMED]
    for arn in confirmed:
        ctx.on_cleanup(lambda arn=arn: _unsubscribe_if_present(sns, arn))
    assert len(set(confirmed)) == _CONFIRMED, f"{_CONFIRMED} sqs subscribes returned {len(set(confirmed))} distinct ARNs"

    _converge(sns, topic, (_CONFIRMED, _PENDING), "after the concurrent subscribes")
    listed = _listed(sns, topic)
    assert sorted(s["Endpoint"] for s in listed) == sorted(queues + mails), (
        f"the topic must list every endpoint once; it lists {len(listed)} subscription(s)")
    assert sorted(s["SubscriptionArn"] for s in listed if s["Protocol"] == "sqs") == sorted(confirmed), (
        "the listed sqs subscriptions are not the ARNs Subscribe returned")

    with ThreadPoolExecutor(max_workers=_REMOVED) as pool:
        list(pool.map(lambda arn: sns.unsubscribe(SubscriptionArn=arn), confirmed[:_REMOVED]))

    _converge(sns, topic, (_CONFIRMED - _REMOVED, _PENDING), "after the concurrent unsubscribes")
    remaining = _listed(sns, topic)
    assert sorted(s["SubscriptionArn"] for s in remaining if s["Protocol"] == "sqs") == sorted(confirmed[_REMOVED:]), (
        f"after removing {_REMOVED}, the topic must list exactly the survivors; it lists "
        f"{sum(1 for s in remaining if s['Protocol'] == 'sqs')} sqs subscription(s)")
    assert sorted(s["Endpoint"] for s in remaining if s["Protocol"] == "email") == sorted(mails), (
        "the concurrent unsubscribes disturbed the pending email subscriptions")


def _unsubscribe_if_present(sns, arn: str) -> None:
    """Teardown for a subscription the check may already have removed: tolerates only that."""
    try:
        sns.unsubscribe(SubscriptionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
