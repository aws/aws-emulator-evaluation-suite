"""sqs-envelope-raw-bytes-are-pretty-printed-in-canonical-key-order."""
from __future__ import annotations

import base64
import json
import re
import time
from urllib.parse import parse_qsl, urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-envelope-raw-bytes-are-pretty-printed-in-canonical-key-order"
GROUP = "envelope-format"
SERVICES = ["sns", "sqs"]

_BARE_KEYS = [
    "Type", "MessageId", "TopicArn", "Message", "Timestamp",
    "SignatureVersion", "Signature", "SigningCertURL", "UnsubscribeURL",
]
_FULL_KEYS = [
    "Type", "MessageId", "TopicArn", "Subject", "Message", "Timestamp",
    "SignatureVersion", "Signature", "SigningCertURL", "UnsubscribeURL", "MessageAttributes",
]
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SNS delivers to SQS a pretty-printed envelope, one `"Key" : value` line per member in the order Type,
    MessageId, TopicArn, [Subject], Message, Timestamp, SignatureVersion, Signature, SigningCertURL,
    UnsubscribeURL, [MessageAttributes]; optional members absent, one compact line per attribute."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-sns-layout-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic), "NotFound"))
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-sns-layout-"),
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

    bare = ctx.unique_name("sim2real-layout-bare-")
    full = ctx.unique_name("sim2real-layout-full-")
    subject = "layout subject"
    attrs = {
        "kind": {"DataType": "String", "StringValue": "plain"},
        "count": {"DataType": "Number", "StringValue": "42"},
        "blob": {"DataType": "Binary", "BinaryValue": b"\x00\x01\xfe"},
    }
    bare_id = sns.publish(TopicArn=topic, Message=bare)["MessageId"]
    full_id = sns.publish(TopicArn=topic, Message=full, Subject=subject,
                          MessageAttributes=attrs)["MessageId"]

    got = _receive(sqs, url, {bare, full})

    for payload, msg_id, keys in ((bare, bare_id, _BARE_KEYS), (full, full_id, _FULL_KEYS)):
        raw = got[payload]
        pairs = json.loads(raw, object_pairs_hook=list)
        order = [k for k, _ in pairs]
        assert order == keys, f"envelope keys for {payload!r} are {order!r}, expected {keys!r}"
        doc = dict(pairs)
        rendered = _render(pairs)
        assert raw == rendered, (
            f"the delivered body is not laid out as SNS writes it; got {raw[:400]!r}, "
            f"expected {rendered[:400]!r}"
        )
        assert doc["Type"] == "Notification", f"Type was {doc['Type']!r}"
        assert doc["MessageId"] == msg_id, (
            f"the envelope MessageId does not match the one Publish returned for {payload!r}"
        )
        assert doc["TopicArn"] == topic, "the envelope TopicArn is not the topic published to"
        assert doc["Message"] == payload, f"Message was {doc['Message']!r}, expected {payload!r}"
        assert doc["SignatureVersion"] == "1", f"SignatureVersion was {doc['SignatureVersion']!r}"
        assert _TIMESTAMP.match(doc["Timestamp"]), f"Timestamp was {doc['Timestamp']!r}"
        unsub = urlsplit(doc["UnsubscribeURL"])
        assert parse_qsl(unsub.query) == [("Action", "Unsubscribe"), ("SubscriptionArn", sub)], (
            f"UnsubscribeURL query was {unsub.query.split('SubscriptionArn=')[0]!r}..., expected "
            "Action=Unsubscribe then this subscription's ARN"
        )

    full_doc = json.loads(got[full])
    assert full_doc["Subject"] == subject, f"Subject was {full_doc['Subject']!r}"
    delivered = full_doc["MessageAttributes"]
    expected = {
        "kind": {"Type": "String", "Value": "plain"},
        "count": {"Type": "Number", "Value": "42"},
        "blob": {"Type": "Binary", "Value": base64.b64encode(b"\x00\x01\xfe").decode()},
    }
    assert delivered == expected, f"envelope MessageAttributes were {delivered!r}, expected {expected!r}"


def _render(pairs: list) -> str:
    """The envelope as SNS lays it out, from its own parsed members."""
    lines = []
    for key, value in pairs:
        if key == "MessageAttributes":
            inner = ",\n".join(
                f"    {json.dumps(name)} : "
                + "{" + ",".join(f"{json.dumps(k)}:{json.dumps(v)}" for k, v in attr) + "}"
                for name, attr in value
            )
            lines.append(f"  {json.dumps(key)} : {{\n{inner}\n  }}")
        else:
            lines.append(f"  {json.dumps(key)} : {json.dumps(value)}")
    return "{\n" + ",\n".join(lines) + "\n}"


def _receive(sqs, url: str, payloads: set, timeout_s: float = 90.0) -> dict:
    """Raw body of the first delivery of each payload, keyed by its Message."""
    got: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and set(got) != payloads:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            message = json.loads(m["Body"]).get("Message")
            if message in payloads:
                got.setdefault(message, m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert set(got) == payloads, (
        f"only {sorted(got)!r} of {sorted(payloads)!r} reached the queue in {timeout_s:.0f}s"
    )
    return got


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
