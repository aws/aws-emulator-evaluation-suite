"""queue-policy-source-account-condition-decides-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "queue-policy-source-account-condition-decides-delivery"
GROUP = "authorization"
SERVICES = ["sns"]

_ROUNDS = 3


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SNS presents the topic owner's account as `aws:SourceAccount` when delivering to SQS: of two
    subscribed queues, the one whose policy requires the caller's account receives every message and the
    one naming another account receives none until its condition is corrected, after which it receives."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    other_account = "111122223333"  # documentation placeholder: an account that is not this one

    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-srcacct-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    good_url, good_arn = _create_queue(ctx, "sim2real-behav-sns-acct-ok-")
    bad_url, bad_arn = _create_queue(ctx, "sim2real-behav-sns-acct-no-")
    _set_queue_policy(sqs, good_url, good_arn, ctx.account)
    _set_queue_policy(sqs, bad_url, bad_arn, other_account)

    for queue in (good_arn, bad_arn):
        sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
        ctx.on_cleanup(lambda s=sub: sns.unsubscribe(SubscriptionArn=s))

    leaked: list[str] = []
    for i in range(_ROUNDS):
        body = ctx.unique_name(f"sim2real-r{i}-")
        assert sns.publish(TopicArn=topic, Message=body)["MessageId"], "Publish must return a MessageId"
        got = _drain_until(sqs, good_url, {body}, 60)
        assert body in got, (
            f"the queue admitting aws:SourceAccount = this account must receive round {i}; got {got!r}"
        )
        leaked += _drain_until(sqs, bad_url, set(), 0)
    leaked += _drain_until(sqs, bad_url, set(), 0)
    assert leaked == [], (
        "the queue whose policy admits SNS only for a different aws:SourceAccount received "
        f"{len(leaked)} message(s) out of {_ROUNDS} published"
    )

    _set_queue_policy(sqs, bad_url, bad_arn, ctx.account)
    deadline = time.monotonic() + 120
    received: list[str] = []
    while time.monotonic() < deadline:
        body = ctx.unique_name("sim2real-repair-")
        sns.publish(TopicArn=topic, Message=body)
        received = _drain_until(sqs, bad_url, {body}, 20)
        if body in received:
            break
    else:
        raise AssertionError(
            "after its aws:SourceAccount condition named this account, the queue still received "
            f"nothing published to the topic; last drain {received!r}"
        )


def _create_queue(ctx, prefix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _set_queue_policy(sqs, url: str, arn: str, account: str) -> None:
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": account}},
        }],
    })
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": policy})
    deadline = time.monotonic() + 60
    while json.loads(sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])
                     ["Attributes"].get("Policy", "{}")) != json.loads(policy):
        assert time.monotonic() < deadline, "the queue policy never read back as set"
        time.sleep(2)


def _drain_until(sqs, url: str, wanted: set[str], timeout_s: float) -> list[str]:
    """Receive and delete until every body in ``wanted`` arrived or the deadline passed (at
    least one receive always runs); returns every notification Message drained."""
    out: list[str] = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"])["Message"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if (wanted and wanted <= set(out)) or time.monotonic() >= deadline:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
