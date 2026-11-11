"""fifo-message-group-and-deduplication-ids-over-128-characters-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-message-group-and-deduplication-ids-over-128-characters-rejected"
GROUP = "fifo-limits"
SERVICES = ["sns"]


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the error ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a FIFO topic, 128-character MessageGroupId and MessageDeduplicationId are accepted and
    delivered under the full group id; 129 in either is refused and never reaches the queue."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-fifolen-") + ".fifo",
                             Attributes={"FifoTopic": "true"},
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-fifolen-") + ".fifo",
                           Attributes={"FifoQueue": "true"}, tags={"sim2real": CHECK})["QueueUrl"]
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

    stem = ctx.unique_name("g")
    g128, d128 = stem + "g" * (128 - len(stem)), stem + "d" * (128 - len(stem))
    g129, d129 = g128 + "x", d128 + "x"

    code, message = _error(lambda: sns.publish(TopicArn=topic, Message="long-group",
                                               MessageGroupId=g129, MessageDeduplicationId=d128))
    assert (code, message) == ("InvalidParameter", "Invalid parameter: The MessageGroupId parameter can only include "
                               "alphanumeric and punctuation characters. 1 to 128 in length"), (
        f"a 129-character MessageGroupId gave {code!r}: {message!r}")
    code, message = _error(lambda: sns.publish(TopicArn=topic, Message="long-dedup",
                                               MessageGroupId=g128, MessageDeduplicationId=d129))
    assert (code, message) == ("InvalidParameter", "Invalid parameter: The MessageDeduplicationId parameter can only include "
                               "alphanumeric and punctuation characters. 1 to 128 in length"), (
        f"a 129-character MessageDeduplicationId gave {code!r}: {message!r}")

    body = ctx.unique_name("sim2real-fifolen-ok-")
    seq = sns.publish(TopicArn=topic, Message=body, MessageGroupId=g128,
                      MessageDeduplicationId=d128).get("SequenceNumber")
    assert seq, "a publish with 128-character ids must be accepted and sequenced"

    got = []
    deadline, tail = time.monotonic() + 90, None
    while time.monotonic() < deadline and (tail is None or time.monotonic() < tail):
        if tail is None and any(b == body for b, _ in got):
            # Keep receiving briefly so a delivered refused message is also caught.
            tail = time.monotonic() + 6
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                     AttributeNames=["MessageGroupId"]).get("Messages", []):
            got.append((m["Body"], m["Attributes"].get("MessageGroupId")))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert got == [(body, g128)], (
        f"the queue must hold only the accepted message, under its full 128-character group id; "
        f"got bodies {[b for b, _ in got]!r}, group id lengths {[len(g or '') for _, g in got]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
