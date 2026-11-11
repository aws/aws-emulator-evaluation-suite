"""fifo-concurrent-publishers-across-many-groups-keep-each-group-in-order."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "fifo-concurrent-publishers-across-many-groups-keep-each-group-in-order"
GROUP = "fifo-ordering"
SERVICES = ["sns"]

_GROUPS = 8
_PER_GROUP = 6


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Eight concurrent publishers, one per FIFO message group, each publish six messages; every
    message is delivered exactly once under its group, and each group arrives in publish order
    with strictly increasing SequenceNumbers.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-fifomany-") + ".fifo",
                             Attributes={"FifoTopic": "true"},
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-fifomany-") + ".fifo",
                           Attributes={"FifoQueue": "true"}, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    q_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": q_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=q_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    run_id = ctx.unique_name("r")

    def publish_group(g: int) -> list[tuple[str, str]]:
        out = []
        for i in range(_PER_GROUP):
            body = f"{run_id}-g{g}-m{i}"
            resp = sns.publish(TopicArn=topic, Message=body, MessageGroupId=f"group-{g}",
                               MessageDeduplicationId=body)
            out.append((body, resp["SequenceNumber"]))
        return out

    with ThreadPoolExecutor(max_workers=_GROUPS) as pool:
        published = dict(enumerate(pool.map(publish_group, range(_GROUPS))))

    for g, sent in published.items():
        seqs = [int(s) for _, s in sent]
        assert all(a < b for a, b in zip(seqs, seqs[1:])), (
            f"group-{g}'s SequenceNumbers must strictly increase in publish order; got {seqs!r}")

    total = _GROUPS * _PER_GROUP
    delivered = _drain(sqs, url, total, 180)
    assert len(delivered) == total, (
        f"all {total} messages must be delivered exactly once; received {len(delivered)}")
    for g, sent in published.items():
        got = [(env["Message"], env.get("SequenceNumber")) for grp, env in delivered if grp == f"group-{g}"]
        assert got == sent, (
            f"group-{g} must arrive in its publish order with the SequenceNumbers Publish returned; "
            f"published {[b.rsplit('-', 1)[1] for b, _ in sent]}, received "
            f"{[b.rsplit('-', 1)[1] for b, _ in got]}")


def _drain(sqs, url: str, want: int, timeout_s: float) -> list[tuple[str, dict]]:
    """(MessageGroupId, envelope) in receive order until ``want`` arrived or the deadline,
    then a short tail to catch duplicates."""
    out: list[tuple[str, dict]] = []
    deadline = time.monotonic() + timeout_s
    tail = None
    while time.monotonic() < deadline and (tail is None or time.monotonic() < tail):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                   AttributeNames=["MessageGroupId"])
        for m in resp.get("Messages", []):
            out.append((m["Attributes"]["MessageGroupId"], json.loads(m["Body"])))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if len(out) >= want and tail is None:
            tail = time.monotonic() + 6
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
