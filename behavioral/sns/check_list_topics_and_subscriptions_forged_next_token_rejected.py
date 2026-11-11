"""list-topics-and-subscriptions-forged-next-token-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-topics-and-subscriptions-forged-next-token-rejected"
GROUP = 'pagination'
SERVICES = ['sns']

_FORGED = "c2ltMnJlYWwtbm90LWEtcmVhbC10b2tlbg=="


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTopics and account-wide ListSubscriptions both refuse a NextToken SNS never
    issued with InvalidParameter, while the same calls without a token, and with a token
    SNS itself issued, keep working.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-forgetok-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    code, message = _error(lambda: sns.list_topics(NextToken=_FORGED))
    assert code == "InvalidParameter", f"ListTopics with a forged NextToken gave {code!r}"
    assert message == "Invalid parameter: NextToken", (
        f"unexpected ListTopics forged-token message: {message!r}"
    )

    code, message = _error(lambda: sns.list_subscriptions(NextToken=_FORGED))
    assert code == "InvalidParameter", f"ListSubscriptions with a forged NextToken gave {code!r}"
    assert message == "Invalid parameter: NextToken", (
        f"unexpected ListSubscriptions forged-token message: {message!r}"
    )

    # Positive controls: the same operations without a token work, and the SNS-driven
    # paginator walk (tokens SNS itself issued) reaches the topic and subscription made here.
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", ReturnSubscriptionArn=True,
        Endpoint=":".join(["arn:aws:sqs"] + topic_arn.split(":")[3:5] + [ctx.unique_name("sim2real-behav-sns-forgetok-q-")]),
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    topics = _poll(
        lambda: {t["TopicArn"] for p in sns.get_paginator("list_topics").paginate() for t in p["Topics"]},
        lambda arns: topic_arn in arns, timeout_s=60.0, interval_s=3.0,
        what="the created topic appears in a paginated ListTopics walk",
    )
    assert topic_arn in topics, "the created topic must be listed"
    subs = _poll(
        lambda: {s["SubscriptionArn"] for p in sns.get_paginator("list_subscriptions").paginate()
                 for s in p["Subscriptions"]},
        lambda arns: sub_arn in arns, timeout_s=60.0, interval_s=3.0,
        what="the created subscription appears in a paginated ListSubscriptions walk",
    )
    assert sub_arn in subs, "the created subscription must be listed"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
