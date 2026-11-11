"""message-attribute-name-outside-the-allowed-charset-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-attribute-name-outside-the-allowed-charset-rejected"
GROUP = "envelope-format"
SERVICES = ["sns", "sqs"]

_ALLOWED = "alphanumeric characters, hyphens, underscores, or dots"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publish refuses a message attribute name holding a space, tab, '#', '/', ':' or '~' with ParameterValueInvalid
    naming the character as an unpadded uppercase hex reference ('#x20', '#x9', '#x2F') and delivers nothing; a
    non-ASCII letter and every allowed punctuation mark are delivered under the published names."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-sns-attrchar-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic), "NotFound"))
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-sns-attrchar-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"))
    q_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": q_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=q_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(_teardown(lambda: sns.unsubscribe(SubscriptionArn=sub), "NotFound"))

    refused = {"a b": "#x20", "a\tb": "#x9", "a#b": "#x23", "a/b": "#x2F",
               "a:b": "#x3A", "a~b": "#x7E"}
    wrong = {}
    for name, ref in refused.items():
        got = _error(lambda name=name: sns.publish(
            TopicArn=topic, Message=f"refused-attrchar-{ref}",
            MessageAttributes={name: {"DataType": "String", "StringValue": "v"}}))
        want = ("ParameterValueInvalid",
                f"Invalid non-alphanumeric character '{ref}' was found in the message "
                f"attribute name. Can only include {_ALLOWED}.")
        if got != want:
            wrong[name] = got
    assert not wrong, f"attribute names outside the charset were not refused as AWS does: {wrong!r}"

    # Positive control on the same subscription: allowed punctuation and a non-ASCII letter.
    marker = ctx.unique_name("sim2real-attrchar-ok-")
    accepted = {"A-b_c.d9": "punct", "café": "letter"}
    start = time.monotonic()
    sns.publish(TopicArn=topic, Message=marker, MessageAttributes={
        n: {"DataType": "String", "StringValue": v} for n, v in accepted.items()})

    seen: list = []
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and marker not in [d.get("Message") for d in seen]:
        seen.extend(_drain_once(sqs, url))
    delivered = [d for d in seen if d.get("Message") == marker]
    assert delivered, f"the accepted publish never reached the queue; saw {len(seen)} other message(s)"
    latency = time.monotonic() - start
    attrs = delivered[0].get("MessageAttributes")
    want_attrs = {n: {"Type": "String", "Value": v} for n, v in accepted.items()}
    assert attrs == want_attrs, f"envelope MessageAttributes were {attrs!r}, expected {want_attrs!r}"

    # The control's arrival is the barrier; keep draining for max(10 s, 3x its latency).
    window_end = time.monotonic() + max(10.0, 3.0 * latency)
    while time.monotonic() < window_end:
        seen.extend(_drain_once(sqs, url))
    leaked = [d.get("Message") for d in seen if str(d.get("Message", "")).startswith("refused-attrchar-")]
    assert leaked == [], f"refused publishes were delivered: {leaked!r}"


def _drain_once(sqs, url: str) -> list:
    out = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                 WaitTimeSeconds=2).get("Messages", []):
        out.append(json.loads(m["Body"]))
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _error(fn) -> tuple:
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the publish to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
