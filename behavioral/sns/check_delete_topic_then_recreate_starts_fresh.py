"""delete-topic-then-recreate-starts-fresh."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "delete-topic-then-recreate-starts-fresh"
GROUP = 'topic-lifecycle'
SERVICES = ['sns']


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A topic recreated under a deleted topic's name gets the same ARN but none of its state:
    no DisplayName, tags, AddPermission statement or subscriptions, and zeroed counters."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-fresh-")
    arn = sns.create_topic(Name=name, Attributes={"DisplayName": "old"},
                           Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "gen", "Value": "1"}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    region, account = arn.split(":")[3:5]
    label = ctx.unique_name("sim2real-behav-lbl-")
    sns.add_permission(TopicArn=arn, Label=label, AWSAccountId=[account], ActionName=["Publish"])
    sub = sns.subscribe(
        TopicArn=arn, Protocol="sqs", ReturnSubscriptionArn=True,
        Endpoint=f"arn:aws:sqs:{region}:{account}:{ctx.unique_name('sim2real-behav-sns-fresh-q-')}",
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    sns.delete_topic(TopicArn=arn)
    again = sns.create_topic(Name=name)["TopicArn"]
    assert again == arn, "a topic recreated under the same name must get the same ARN"

    attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
    assert attrs.get("DisplayName") == "", (
        f"the recreated topic must not inherit DisplayName, got {attrs.get('DisplayName')!r}"
    )
    sids = {s.get("Sid") for s in json.loads(attrs["Policy"]).get("Statement", [])}
    assert label not in sids, "the recreated topic must not inherit the old AddPermission statement"
    tags_now = sns.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_now == [], f"the recreated topic must have no tags, got {len(tags_now)} tag(s)"

    subs = _poll(
        lambda: sns.list_subscriptions_by_topic(TopicArn=arn)["Subscriptions"],
        lambda v: v == [], timeout_s=90.0, interval_s=3.0,
        what="the recreated topic lists no subscriptions",
    )
    assert subs == [], "the recreated topic must not inherit the old subscription"
    counters = _poll(
        lambda: {k: sns.get_topic_attributes(TopicArn=arn)["Attributes"].get(k)
                 for k in ("SubscriptionsConfirmed", "SubscriptionsPending")},
        lambda v: v == {"SubscriptionsConfirmed": "0", "SubscriptionsPending": "0"},
        timeout_s=90.0, interval_s=3.0, what="the recreated topic's subscription counters read zero",
    )
    assert counters == {"SubscriptionsConfirmed": "0", "SubscriptionsPending": "0"}, counters


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
