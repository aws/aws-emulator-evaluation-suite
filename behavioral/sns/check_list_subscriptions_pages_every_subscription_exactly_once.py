"""list-subscriptions-pages-every-subscription-exactly-once."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-subscriptions-pages-every-subscription-exactly-once"
GROUP = "pagination"
SERVICES = ["sns"]

_SCENARIO = "sns-list-subscriptions-paging"

_COUNT = 101


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Account-wide ListSubscriptions pages with NextToken, returns each of 101 subscriptions
    on one topic exactly once with its own Protocol, Endpoint, TopicArn and Owner, and drops
    one after it is unsubscribed.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    prefix = ctx.unique_name("sim2real-behav-lsq-")
    endpoints: dict[str, str] = {}
    for i in range(_COUNT):
        # SNS accepts a well-formed SQS ARN for a queue that does not exist.
        endpoint = f"arn:aws:sqs:{ctx.region}:{ctx.account}:{prefix}-{i:03d}"
        sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=endpoint,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
        ctx.on_cleanup(lambda s=sub: ctx.client("sns").unsubscribe(SubscriptionArn=s))
        endpoints[sub] = endpoint

    def _ours() -> tuple[list[dict], list[int], bool]:
        rows: list[dict] = []
        sizes: list[int] = []
        token = None
        while True:
            kwargs = {"NextToken": token} if token else {}
            page = sns.list_subscriptions(**kwargs)
            sizes.append(len(page.get("Subscriptions", [])))
            # The listing is account-wide; only this check's topic is asserted on.
            rows.extend(s for s in page.get("Subscriptions", [])
                        if s.get("TopicArn") == topic_arn)
            token = page.get("NextToken")
            if not token:
                return rows, sizes, len(sizes) > 1

    def _each_once(rows: list[dict], wanted: set[str]) -> bool:
        # A walk that overlaps another writer's Subscribe or Unsubscribe may shift page
        # boundaries; a walk is graded once it lists exactly the wanted rows, each once.
        arns = [s["SubscriptionArn"] for s in rows]
        return len(arns) == len(set(arns)) and set(arns) == wanted

    rows, sizes, paged = _poll_until(
        _ours, lambda r: _each_once(r[0], set(endpoints)),
        timeout_s=90.0, interval_s=3.0,
        description=f"all {_COUNT} subscriptions appear in ListSubscriptions")

    assert paged, f"more than 100 subscriptions must span several pages, got page sizes {sizes!r}"
    assert max(sizes) <= 100, f"a ListSubscriptions page held more than 100 entries: {sizes!r}"
    arns = [s["SubscriptionArn"] for s in rows]
    assert len(arns) == len(set(arns)) == _COUNT, (
        f"each subscription must appear exactly once across pages; got {len(arns)} rows, "
        f"{len(set(arns))} distinct, expected {_COUNT}"
    )
    assert set(arns) == set(endpoints), (
        f"the listed subscriptions must be exactly the ones created; "
        f"{len(set(arns) - set(endpoints))} unknown, {len(set(endpoints) - set(arns))} missing"
    )
    wrong = [s["SubscriptionArn"] for s in rows
             if s.get("Protocol") != "sqs" or s.get("Endpoint") != endpoints[s["SubscriptionArn"]]
             or s.get("Owner") != ctx.account]
    assert wrong == [], (
        f"{len(wrong)} listed subscriptions do not carry their own Protocol 'sqs', Endpoint "
        f"and Owner (the account)"
    )

    gone = arns[0]
    sns.unsubscribe(SubscriptionArn=gone)
    rows, _sizes, _paged = _poll_until(
        _ours, lambda r: _each_once(r[0], set(endpoints) - {gone}),
        timeout_s=90.0, interval_s=3.0,
        description="the unsubscribed subscription leaves ListSubscriptions")
    remaining = {s["SubscriptionArn"] for s in rows}
    assert remaining == set(endpoints) - {gone}, (
        f"after one Unsubscribe the topic must list exactly the other {_COUNT - 1}; got "
        f"{len(remaining)}"
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
    name = ctx.unique_name("sim2real-behav-sns-t-") + (".fifo" if fifo else "")
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
    name = ctx.unique_name("sim2real-behav-sns-q-") + (".fifo" if fifo else "")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
