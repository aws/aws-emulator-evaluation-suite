"""publish-batch-aggregate-size-at-the-exact-262144-byte-boundary."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-batch-aggregate-size-at-the-exact-262144-byte-boundary"
GROUP = "publish-batch-limits"
SERVICES = ["sns"]

_SCENARIO = "sns-publish-batch-aggregate-boundary"
_LIMIT_BYTES = 262144


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PublishBatch bodies totalling exactly 262144 bytes are accepted and delivered intact, while
    one byte more (262145) refuses the whole batch with BatchRequestTooLong.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn, attributes={"RawMessageDelivery": "true"})

    run_id = ctx.unique_name("sim2real-behav-sns-aggbound-")
    head_a = f"{run_id}-a-"
    head_b = f"{run_id}-b-"
    half = _LIMIT_BYTES // 2
    body_a_ok = head_a + "a" * (half - len(head_a))
    body_b_ok = head_b + "b" * (_LIMIT_BYTES - half - len(head_b))
    assert len(body_a_ok) + len(body_b_ok) == _LIMIT_BYTES, (
        f"boundary bodies total {len(body_a_ok) + len(body_b_ok)} bytes, expected {_LIMIT_BYTES}"
    )

    resp = sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=[
        {"Id": "a", "Message": body_a_ok}, {"Id": "b", "Message": body_b_ok}])
    assert resp.get("Failed", []) == [], (
        f"a batch whose bodies total exactly {_LIMIT_BYTES} bytes must be accepted, got Failed "
        f"{resp.get('Failed')!r}"
    )
    assert sorted(e["Id"] for e in resp.get("Successful", [])) == ["a", "b"], (
        f"expected both entries Successful, got {resp.get('Successful')!r}"
    )

    delivered = _await_bodies(ctx, queue_url, {body_a_ok, body_b_ok}, timeout_s=90.0,
                              description="the exact-boundary batch is delivered intact")
    assert set(delivered) == {body_a_ok, body_b_ok}, (
        f"the boundary batch's bodies must arrive byte-for-byte unmodified, got {sorted(delivered)!r}"
    )

    body_b_over = body_b_ok + "z"
    code, message = _error(lambda: sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=[
        {"Id": "a2", "Message": body_a_ok}, {"Id": "b2", "Message": body_b_over}]))
    assert code == "BatchRequestTooLong", (
        f"a batch whose bodies total {_LIMIT_BYTES + 1} bytes (one over the boundary) gave "
        f"{code!r}, expected 'BatchRequestTooLong'; message {message!r}"
    )
    assert message == "The length of all the messages put together is more than the limit.", (
        f"unexpected refusal message {message!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately; returns the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-aggbound-")
    arn = sns.create_topic(Name=name, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-aggbound-q-")
    url = sqs.create_queue(
        QueueName=name, tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
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
                           attributes: dict | None = None, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    deadline = time.monotonic() + timeout_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return sub_arn
        time.sleep(1.0)
    raise AssertionError(
        f"subscription {sub_arn!r} was still PendingConfirmation={pending!r} after {timeout_s}s"
    )


def _await_bodies(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                  description: str) -> list[str]:
    """Long-poll until every wanted body is seen; RAISES on the deadline. Returns what was seen."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg["Body"]
            seen.append(body)
            outstanding.discard(body)
        if outstanding and time.monotonic() >= deadline:
            raise AssertionError(f"{description}: {len(outstanding)} body(ies) never arrived within {timeout_s}s")
    return seen


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
