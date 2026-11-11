"""fifo-message-group-dedup-scope-holds-per-group-under-concurrent-publishers."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "fifo-message-group-dedup-scope-holds-per-group-under-concurrent-publishers"
GROUP = "fifo-dedup"
SERVICES = ["sns"]

_GROUPS = 10
_REPEATS = 3


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """With FifoThroughputScope=MessageGroup, ten concurrent per-group publishers each send three
    bodies under one shared MessageDeduplicationId; exactly one message per group is delivered,
    that group's first, so deduplication is scoped per group.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-fifoscope-") + ".fifo",
                             Attributes={"FifoTopic": "true", "FifoThroughputScope": "MessageGroup"},
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    scope = sns.get_topic_attributes(TopicArn=topic)["Attributes"].get("FifoThroughputScope")
    assert scope == "MessageGroup", f"the topic's FifoThroughputScope reads {scope!r}"
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-fifoscope-") + ".fifo",
                           Attributes={"FifoQueue": "true", "DeduplicationScope": "messageGroup",
                                       "FifoThroughputLimit": "perMessageGroupId"},
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    q_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": q_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=q_arn, ReturnSubscriptionArn=True,
                        Attributes={"RawMessageDelivery": "true"})["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    run_id = ctx.unique_name("r")
    shared = f"{run_id}-shared"

    def publish_group(g: int) -> str:
        first = None
        for i in range(_REPEATS):
            body = f"{run_id}-g{g}-try{i}"
            sns.publish(TopicArn=topic, Message=body, MessageGroupId=f"group-{g}",
                        MessageDeduplicationId=shared)
            first = first or body
        return first

    with ThreadPoolExecutor(max_workers=_GROUPS) as pool:
        firsts = dict(enumerate(pool.map(publish_group, range(_GROUPS))))

    delivered = _drain(sqs, url, _GROUPS, 120)
    by_group: dict[str, list[str]] = {}
    for grp, body in delivered:
        by_group.setdefault(grp, []).append(body)
    expected = {f"group-{g}": [first] for g, first in firsts.items()}
    assert by_group == expected, (
        f"each group must deliver exactly its first publish under the shared deduplication id; "
        f"got {len(delivered)} message(s) across {len(by_group)} group(s): "
        f"{ {g: [b.rsplit('-', 1)[1] for b in bs] for g, bs in sorted(by_group.items())} }")


def _drain(sqs, url: str, want: int, timeout_s: float) -> list[tuple[str, str]]:
    """(MessageGroupId, body) until ``want`` arrived or the deadline, then a tail that would
    catch any repeat that escaped deduplication."""
    out: list[tuple[str, str]] = []
    deadline = time.monotonic() + timeout_s
    tail = None
    while time.monotonic() < deadline and (tail is None or time.monotonic() < tail):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                   AttributeNames=["MessageGroupId"])
        for m in resp.get("Messages", []):
            out.append((m["Attributes"]["MessageGroupId"], m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if len(out) >= want and tail is None:
            tail = time.monotonic() + 8
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
