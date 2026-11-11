"""subscribe-invalid-filter-policy-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscribe-invalid-filter-policy-fails"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']

def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, HTTP status). Raises if the call unexpectedly
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), err.get("Message", ""), status
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_topic(ctx, name=None, attributes=None, tags=None, fifo=False):
    """Create a topic, register its teardown, and return its ARN."""
    sns = ctx.client("sns")
    name = name or ctx.unique_name("sim2real-behav-sns-topic-")
    if fifo and not name.endswith(".fifo"):
        name = f"{name}.fifo"
    kwargs = {"Name": name}
    attrs = dict(attributes) if attributes else {}
    if fifo:
        attrs.setdefault("FifoTopic", "true")
    if attrs:
        kwargs["Attributes"] = attrs
    if tags:
        kwargs["Tags"] = tags
    arn = sns.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue(ctx, fifo=False):
    """Create an SQS queue (SQS subscriptions auto-confirm, unlike email/http);
    return (queue_url, queue_arn)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attrs: dict[str, str] = {}
    if fifo:
        name = f"{name}.fifo"
        attrs["FifoQueue"] = "true"
    kwargs: dict = {"QueueName": name, "tags": {"sim2real": "true"}}
    if attrs:
        kwargs["Attributes"] = attrs
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Subscribe with an unparseable FilterPolicy is refused with InvalidParameter (HTTP 400) and an
    exact message and creates nothing, while a well-formed FilterPolicy on the same topic and
    queue is accepted and auto-confirmed."""
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx, tags=[{"Key": "sim2real", "Value": "true"}])
    _, queue_arn = _create_queue(ctx)

    good_sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        Attributes={"FilterPolicy": json.dumps({"event": ["created"]})},
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    assert good_sub_arn and good_sub_arn != "pending confirmation", (
        f"expected the control subscription auto-confirmed, got {good_sub_arn!r}"
    )
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=good_sub_arn))

    code, message, status = _error(
        lambda: sns.subscribe(
            TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
            Attributes={"FilterPolicy": "this-is-not-json"},
            ReturnSubscriptionArn=True,
        )
    )
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r} ({message!r})"
    assert status == 400, f"expected HTTP 400 for the refusal, got {status!r}"
    expected_message = "Invalid parameter: Attributes Reason: FilterPolicy: failed to parse JSON. Unrecognized token 'this': was expecting (JSON String, Number, Array, Object or token 'null', 'true' or 'false')\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 1]"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    sub_arns = [s["SubscriptionArn"] for s in subs]
    assert sub_arns == [good_sub_arn], (
        f"the rejected Subscribe must not create a subscription; expected only "
        f"[{good_sub_arn!r}], got {sub_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
