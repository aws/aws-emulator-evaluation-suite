"""delivery-to-a-kms-encrypted-queue-withheld-until-the-key-policy-grants-sns."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delivery-to-a-kms-encrypted-queue-withheld-until-the-key-policy-grants-sns"
GROUP = "kms-integration"
SERVICES = ["kms", "sns", "sqs"]

_SCENARIO = "sns-to-sse-kms-queue"


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SNS withholds delivery to an SSE-KMS queue whose key policy does not grant
    sns.amazonaws.com while a granted twin queue receives every message; adding the grant
    to the key policy makes the same queue receive.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    topic_arn = _create_topic(ctx)

    granted_key = _create_key(ctx, grant_sns=True)
    ungranted_key = _create_key(ctx, grant_sns=False)
    granted_url, granted_arn = _create_queue_for_topic(
        ctx, topic_arn, attributes={"KmsMasterKeyId": granted_key})
    ungranted_url, ungranted_arn = _create_queue_for_topic(
        ctx, topic_arn, attributes={"KmsMasterKeyId": ungranted_key})
    _subscribe_and_confirm(ctx, topic_arn, granted_arn,
                           attributes={"RawMessageDelivery": "true"})
    _subscribe_and_confirm(ctx, topic_arn, ungranted_arn,
                           attributes={"RawMessageDelivery": "true"})

    # Positive control for the queue itself: the account can send to the ungranted queue
    # directly, so its key works and only SNS's use of it is missing.
    direct = ctx.unique_name("sim2real-xsvc-ssekmsq-direct-")
    sqs.send_message(QueueUrl=ungranted_url, MessageBody=direct)
    _await_bodies(ctx, ungranted_url, {direct}, timeout_s=60.0,
                  description="a direct SendMessage to the ungranted queue is received")

    marks = [ctx.unique_name(f"sim2real-xsvc-ssekmsq-m{i}-") for i in range(1, 4)]
    # The granted twin receiving all three is what makes the ungranted queue's silence mean
    # "withheld"; the drain window scales with its observed latency.
    started = time.monotonic()
    for marker in marks:
        sns.publish(TopicArn=topic_arn, Message=marker)
    seen = _await_bodies(ctx, granted_url, set(marks), timeout_s=120.0,
                         description="the queue whose key grants SNS receives every message")
    latency = max(max(seen.values()) - started, 1.0)
    window = max(3.0 * latency, 15.0)
    leaked = _drain(ctx, {"ungranted": ungranted_url}, window_s=window)
    assert leaked == {"ungranted": []}, (
        f"the queue whose key policy does not grant SNS must receive nothing from the topic; "
        f"during a {window:.0f}s window after its twin received all three it got {leaked!r}"
    )

    kms.put_key_policy(KeyId=ungranted_key, PolicyName="default",
                       Policy=json.dumps(_key_policy(ctx, grant_sns=True)))

    repaired = None
    deadline = time.monotonic() + 150.0
    received: list[str] = []
    while repaired is None:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"after the key policy granted SNS, no republished message reached the queue "
                f"within 150s; it received {received!r}")
        marker = ctx.unique_name("sim2real-xsvc-ssekmsq-repaired-")
        sns.publish(TopicArn=topic_arn, Message=marker)
        attempt_end = time.monotonic() + 15.0
        while time.monotonic() < attempt_end and repaired is None:
            for msg in sqs.receive_message(QueueUrl=ungranted_url, MaxNumberOfMessages=10,
                                           WaitTimeSeconds=5).get("Messages", []):
                sqs.delete_message(QueueUrl=ungranted_url, ReceiptHandle=msg["ReceiptHandle"])
                received.append(msg["Body"])
                if msg["Body"].startswith("sim2real-xsvc-ssekmsq-repaired-"):
                    repaired = msg["Body"]
    stored = json.loads(kms.get_key_policy(KeyId=ungranted_key, PolicyName="default")["Policy"])
    sids = sorted(s.get("Sid") for s in stored["Statement"])
    assert sids == ["AccountAdministers", "SnsEncryptsIntoTheQueue"], (
        f"the repaired key policy must hold exactly the two statements, got Sids {sids!r}"
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
