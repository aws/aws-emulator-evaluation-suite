"""sse-kms-topic-delivers-plaintext-to-sqs-subscribers."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sse-kms-topic-delivers-plaintext-to-sqs-subscribers"
GROUP = "kms-integration"
SERVICES = ["kms", "sns", "sqs"]

_SCENARIO = "sns-sse-kms-topic-delivery"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A topic encrypted with a customer managed key delivers plaintext to SQS subscribers:
    the raw queue gets the exact body, the enveloped one the published Message, Subject and
    MessageAttributes.
    """
    sns = ctx.client("sns")
    key_arn = _create_key(ctx, grant_sns=False)
    topic_arn = _create_topic(ctx, attributes={"KmsMasterKeyId": key_arn})
    stored = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"].get("KmsMasterKeyId")
    assert stored == key_arn, (
        "GetTopicAttributes must echo the key ARN given as KmsMasterKeyId verbatim; got a "
        f"{'missing' if stored is None else 'different'} value"
    )

    raw_url, raw_arn = _create_queue_for_topic(ctx, topic_arn)
    env_url, env_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, raw_arn, attributes={"RawMessageDelivery": "true"})
    _subscribe_and_confirm(ctx, topic_arn, env_arn)

    body = ctx.unique_name("sim2real-xsvc-ssekms-body-") + " café ✓"
    resp = sns.publish(TopicArn=topic_arn, Message=body, Subject="encrypted at rest",
                       MessageAttributes={"tenant": _s("blue")})
    message_id = resp["MessageId"]

    _await_bodies(ctx, raw_url, {body}, timeout_s=120.0,
                  description="the raw subscriber of the encrypted topic receives the plaintext")

    sqs = ctx.client("sqs")
    envelope = None
    deadline = time.monotonic() + 120.0
    while envelope is None:
        for msg in sqs.receive_message(QueueUrl=env_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=env_url, ReceiptHandle=msg["ReceiptHandle"])
            envelope = json.loads(msg["Body"])
        if envelope is None and time.monotonic() >= deadline:
            raise AssertionError("the enveloped subscriber received nothing within 120s")
    assert envelope.get("Type") == "Notification", f"envelope Type {envelope.get('Type')!r}"
    assert envelope.get("MessageId") == message_id, (
        "the envelope must carry the MessageId Publish returned"
    )
    assert envelope.get("Message") == body, (
        f"the envelope Message must be the plaintext {body!r}, got {envelope.get('Message')!r}"
    )
    assert envelope.get("Subject") == "encrypted at rest", (
        f"the envelope Subject is {envelope.get('Subject')!r}"
    )
    assert envelope.get("MessageAttributes") == {"tenant": {"Type": "String", "Value": "blue"}}, (
        f"the envelope MessageAttributes are {envelope.get('MessageAttributes')!r}"
    )


def _s(value: str) -> dict:
    """A String-typed message attribute value."""
    return {"DataType": "String", "StringValue": value}


def _n(value: str) -> dict:
    """A Number-typed message attribute value."""
    return {"DataType": "Number", "StringValue": value}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, fifo: bool = False, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-xsvc-sns-t-") + (".fifo" if fifo else "")
    attrs = dict(attributes or {})
    if fifo:
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False,
                            attributes: dict | None = None) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-sns-q-") + (".fifo" if fifo else "")
    attrs = dict(attributes or {})
    if fifo:
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *,
                           attributes: dict | None = None,
                           timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation"),
        lambda pending: pending == "false",
        timeout_s=timeout_s, interval_s=2.0,
        description="the new subscription leaves PendingConfirmation",
    )
    return sub_arn


def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value


def _await_bodies(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                  description: str, forbidden: set[str] | None = None) -> dict[str, float]:
    """Long-poll until every wanted body is seen; RAISES on the deadline.

    Returns {body: monotonic time first seen}. A body in `forbidden` that arrives raises at
    once: it is a leak, and swallowing it would hide what the caller is about to assert.
    """
    sqs = ctx.client("sqs")
    seen: dict[str, float] = {}
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg["Body"]
            if forbidden and body in forbidden:
                raise AssertionError(
                    f"{description}: a body that must never be delivered arrived: {body!r}")
            if body in outstanding:
                outstanding.discard(body)
                seen[body] = time.monotonic()
        if outstanding and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(outstanding)} never arrived within {timeout_s}s")
    return seen


def _drain(ctx, queues: dict[str, str], *, window_s: float) -> dict[str, list[str]]:
    """Alternate long polls across the queues for one shared window and return every body
    each produced. The empty lists feed an equality-to-empty assertion."""
    sqs = ctx.client("sqs")
    out: dict[str, list[str]] = {label: [] for label in queues}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        for label, url in queues.items():
            resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=2)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
                out[label].append(msg["Body"])
    return out


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises. An unexpected success
    raises too, naming what came back, so it can never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_key(ctx, *, grant_sns: bool) -> str:
    """A symmetric customer managed key; returns its ARN. Its deletion is scheduled at the
    7-day minimum, registered immediately so LIFO runs it after everything that uses it."""
    kms = ctx.client("kms")
    kwargs: dict = {
        "Description": ctx.unique_name("sim2real-xsvc-kmssnssqs-"),
        "Tags": [{"TagKey": "sim2real", "TagValue": _SCENARIO}],
    }
    if grant_sns:
        kwargs["Policy"] = json.dumps(_key_policy(ctx, grant_sns=True))
    arn = kms.create_key(**kwargs)["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("kms").schedule_key_deletion(
        KeyId=a, PendingWindowInDays=7))
    return arn


def _key_policy(ctx, *, grant_sns: bool) -> dict:
    """The default key policy (the account administers and uses the key), plus, when asked,
    the documented grant that lets SNS encrypt into an SSE-KMS queue."""
    statements = [{
        "Sid": "AccountAdministers",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }]
    if grant_sns:
        statements.append({
            "Sid": "SnsEncryptsIntoTheQueue",
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
            "Resource": "*",
        })
    return {"Version": "2012-10-17", "Statement": statements}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
