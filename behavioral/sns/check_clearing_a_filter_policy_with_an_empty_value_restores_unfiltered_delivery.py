"""clearing-a-filter-policy-with-an-empty-value-restores-unfiltered-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "clearing-a-filter-policy-with-an-empty-value-restores-unfiltered-delivery"
GROUP = 'filter-policy'
SERVICES = ['sns']

_SCENARIO = "sns-filter-policy-clear"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An empty FilterPolicy removes the attribute and the filter in effect: a blue message withheld
    under {"color": ["red"]} is delivered once the policy is cleared, as is one with no attributes.
    An unfiltered twin subscription bounds each wait."""
    sns = ctx.client("sns")
    topic = _create_topic(ctx)
    filtered_url, filtered_arn = _create_queue_for_topics(ctx, [topic])
    twin_url, twin_arn = _create_queue_for_topics(ctx, [topic])
    sub = _subscribe_and_confirm(ctx, topic, filtered_arn,
                                 {"FilterPolicy": json.dumps({"color": ["red"]})})
    _subscribe_and_confirm(ctx, topic, twin_arn)
    run_id = ctx.unique_name("sim2real-behav-sns-fpclear-")

    def publish(body: str, color: str | None) -> None:
        attrs = {"color": {"DataType": "String", "StringValue": color}} if color else {}
        sns.publish(TopicArn=topic, Message=body, MessageAttributes=attrs)

    blue, red = f"{run_id}-blue-filtered", f"{run_id}-red"
    publish(blue, "blue")
    publish(red, "red")
    _drain_until(ctx, twin_url, {blue, red})
    seen = _drain_until(ctx, filtered_url, {red})
    assert blue not in seen, "the blue message was delivered through the red-only filter"

    sns.set_subscription_attributes(SubscriptionArn=sub, AttributeName="FilterPolicy",
                                    AttributeValue="")
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    assert "FilterPolicy" not in attrs, (
        f"an empty FilterPolicy must remove the attribute, it reads {attrs.get('FilterPolicy')!r}")

    seen_blue = None
    for attempt in range(8):
        body = f"{run_id}-blue-after-clear-{attempt}"
        publish(body, "blue")
        _drain_until(ctx, twin_url, {body})
        got = _receive_for(ctx, filtered_url, 10.0)
        if any(k.startswith(f"{run_id}-blue-after-clear-") for k in got):
            seen_blue = body
            break
    assert seen_blue, "after clearing the FilterPolicy, 8 blue publishes were all still withheld"

    bare = f"{run_id}-no-attributes"
    publish(bare, None)
    _drain_until(ctx, filtered_url, {bare})


def _receive_for(ctx, url: str, window_s: float) -> dict:
    """Receive (and delete) everything that arrives within ``window_s``; key -> message."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=2).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[_key(msg)] = msg
    return seen


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, prefix: str = "sim2real-behav-sns-t-") -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name(prefix), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: sns.delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topics(ctx, topic_arns: list[str]) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly these topics send to it."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sns-q-"),
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": list(topic_arns)}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, attributes=None,
                           timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue, register Unsubscribe, poll until PendingConfirmation is false."""
    sns = ctx.client("sns")
    kwargs = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
              "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: _unsubscribe_if_present(sns, s))
    deadline = time.monotonic() + timeout_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return sub_arn
        time.sleep(1.0)
    raise AssertionError(
        f"the sqs subscription was still PendingConfirmation={pending!r} after {timeout_s}s")


def _unsubscribe_if_present(sns, sub_arn: str) -> None:
    """Unsubscribe; a subscription already removed with its topic is the tolerated outcome."""
    try:
        sns.unsubscribe(SubscriptionArn=sub_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


def _key(msg) -> str:
    """The published text of a delivered SQS message: the envelope's Message, else the raw body."""
    body = msg.get("Body", "")
    try:
        env = json.loads(body)
    except ValueError:
        return body
    if isinstance(env, dict) and env.get("Type") == "Notification":
        return env.get("Message", "")
    return body


def _drain_until(ctx, url: str, wanted: set[str], timeout_s: float = 90.0) -> dict:
    """Receive (and delete) until every key in ``wanted`` has been seen; return key -> message
    for EVERY message seen on the way, so a caller can assert what else arrived."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(seen):
        for msg in sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                MessageAttributeNames=["All"], MessageSystemAttributeNames=["All"],
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[_key(msg)] = msg
    missing = sorted(wanted - set(seen))
    assert not missing, (
        f"within {timeout_s}s the queue never received {missing!r}; it received {sorted(seen)!r}")
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
