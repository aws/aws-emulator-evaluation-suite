"""filter-policy-over-150-value-combinations-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-policy-over-150-value-combinations-rejected"
GROUP = "filter-policy-limits"
SERVICES = ["sns"]


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the error ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _policy(*sizes: int) -> dict:
    """One key per size, each matching that many distinct string values."""
    return {f"k{i}": [f"v{i}-{j}" for j in range(n)] for i, n in enumerate(sizes)}


def _current(sns, sub: str) -> dict:
    return json.loads(sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]["FilterPolicy"])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A filter policy of 5x5x6 = 150 value combinations is accepted by SetSubscriptionAttributes
    and Subscribe; 5x5x7 = 175 is refused on both with InvalidParameter "too complex", leaving
    the previous policy in place and creating no subscription.
    """
    sns = ctx.client("sns")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-fpcx-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    region, account = topic.split(":")[3], topic.split(":")[4]

    def queue_arn() -> str:
        # SNS confirms an sqs subscription without resolving the queue.
        return f"arn:aws:sqs:{region}:{account}:sim2real-behav-sns-fpcx-{uuid.uuid4().hex[:8]}"

    at_limit, over = _policy(5, 5, 6), _policy(5, 5, 7)
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn(), ReturnSubscriptionArn=True,
                        Attributes={"FilterPolicy": json.dumps(_policy(2))})["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    sns.set_subscription_attributes(SubscriptionArn=sub, AttributeName="FilterPolicy",
                                    AttributeValue=json.dumps(at_limit))
    assert _current(sns, sub) == at_limit, "a 150-combination filter policy must be accepted and stored"

    code, message = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=sub, AttributeName="FilterPolicy", AttributeValue=json.dumps(over)))
    assert (code, message) == ("InvalidParameter", "Invalid parameter: FilterPolicy: Filter policy is too complex"), (
        f"a 175-combination filter policy on SetSubscriptionAttributes gave {code!r}: {message!r}")
    assert _current(sns, sub) == at_limit, "the refused policy replaced the subscription's previous one"

    code, message = _error(lambda: sns.subscribe(
        TopicArn=topic, Protocol="sqs", Endpoint=queue_arn(), ReturnSubscriptionArn=True,
        Attributes={"FilterPolicy": json.dumps(over)}))
    assert (code, message) == ("InvalidParameter",
                               "Invalid parameter: Attributes Reason: FilterPolicy: Filter policy is too complex"), (
        f"a 175-combination filter policy on Subscribe gave {code!r}: {message!r}")
    subs = [s["SubscriptionArn"] for p in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic)
            for s in p["Subscriptions"]]
    assert subs == [sub], f"the refused Subscribe changed the topic's subscriptions; it lists {len(subs)}"

    second = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn(), ReturnSubscriptionArn=True,
                           Attributes={"FilterPolicy": json.dumps(at_limit)})["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=second))
    assert _current(sns, second) == at_limit, "Subscribe must accept a 150-combination filter policy"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
