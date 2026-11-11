"""lambda-subscription-invocation-carries-the-sns-records-envelope."""
from __future__ import annotations

import base64
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-subscription-invocation-carries-the-sns-records-envelope"
GROUP = "lambda-delivery"
SERVICES = ["sns"]

_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda subscription gets a one-record `Records` event (aws:sns 1.0, its subscription
    ARN) whose `Sns` object uses `...Url` casing, reports a Number attribute as Type String and
    a Binary one base64-encoded, and carries Subject null when none was published.
    """
    sns = ctx.client("sns")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-lrec-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    fn_arn, capture = _capturing_function(ctx, topic)

    sub = sns.subscribe(TopicArn=topic, Protocol="lambda", Endpoint=fn_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    body = ctx.unique_name("sim2real-lrec-body-")
    subject = "sim2real subject line"
    blob = b"\x00\x01sim2real\xff"
    with_subject = sns.publish(TopicArn=topic, Message=body, Subject=subject, MessageAttributes={
        "color": {"DataType": "String", "StringValue": "blue"},
        "count": {"DataType": "Number", "StringValue": "42"},
        "blob": {"DataType": "Binary", "BinaryValue": blob},
    })["MessageId"]
    bare_body = ctx.unique_name("sim2real-lrec-bare-")
    bare = sns.publish(TopicArn=topic, Message=bare_body)["MessageId"]

    events = _captured(ctx, capture, lambda evs: {with_subject, bare} <= _ids(evs), 180)
    assert {with_subject, bare} <= _ids(events), (
        f"the function must be invoked for both publishes; saw MessageIds for "
        f"{len(_ids(events) & {with_subject, bare})} of 2 in {len(events)} event(s)")

    for event in events:
        assert set(event) == {"Records"}, f"the Lambda event's top-level keys are {sorted(event)!r}"
        assert len(event["Records"]) == 1, (
            f"SNS invokes a function with one record per notification; got {len(event['Records'])}")

    record = _record(events, with_subject)
    assert (record.get("EventSource"), record.get("EventVersion")) == ("aws:sns", "1.0"), (
        f"the record's EventSource/EventVersion are {record.get('EventSource')!r}/"
        f"{record.get('EventVersion')!r}")
    assert record.get("EventSubscriptionArn") == sub, (
        "the record's EventSubscriptionArn must be the subscription that delivered it")
    msg = record["Sns"]
    assert (msg.get("Type"), msg.get("MessageId"), msg.get("TopicArn"), msg.get("Message"),
            msg.get("Subject")) == ("Notification", with_subject, topic, body, subject), (
        f"the Sns object must carry the notification as published; got Type {msg.get('Type')!r}, "
        f"Subject {msg.get('Subject')!r}, Message matches={msg.get('Message') == body}, "
        f"MessageId matches={msg.get('MessageId') == with_subject}")
    assert {"SigningCertUrl", "UnsubscribeUrl"} <= set(msg) and not (
            {"SigningCertURL", "UnsubscribeURL"} & set(msg)), (
        f"the Lambda event spells SigningCertUrl/UnsubscribeUrl (not the ...URL envelope form); "
        f"keys were {sorted(msg)!r}")
    assert msg.get("SignatureVersion") == "1" and msg.get("Signature"), (
        f"the notification must be signed (SignatureVersion '1'); got {msg.get('SignatureVersion')!r}")
    assert _TIMESTAMP.match(msg.get("Timestamp") or ""), f"Timestamp is {msg.get('Timestamp')!r}"
    assert msg.get("MessageAttributes") == {
        "color": {"Type": "String", "Value": "blue"},
        "count": {"Type": "String", "Value": "42"},
        "blob": {"Type": "Binary", "Value": base64.b64encode(blob).decode("ascii")},
    }, f"MessageAttributes in the Lambda event are {msg.get('MessageAttributes')!r}"

    plain = _record(events, bare)["Sns"]
    assert "Subject" in plain and plain["Subject"] is None, (
        f"a publish without a Subject must carry Subject null in the Lambda event; got "
        f"{plain.get('Subject', '<absent>')!r}")
    assert plain.get("MessageAttributes") == {}, (
        f"a publish without attributes must carry an empty MessageAttributes map; got "
        f"{plain.get('MessageAttributes', '<absent>')!r}")
    assert plain.get("Message") == bare_body, "the second notification's Message changed in transit"


def _ids(events: list[dict]) -> set[str]:
    return {r.get("Sns", {}).get("MessageId") for e in events for r in e.get("Records", [])}


def _record(events: list[dict], message_id: str) -> dict:
    found = [r for e in events for r in e.get("Records", [])
             if r.get("Sns", {}).get("MessageId") == message_id]
    assert found, "no record for the published MessageId was captured"
    return found[0]


# The subscribed function copies the event it was invoked with into a capture queue. Its role
# can only send to that queue and has no CloudWatch Logs permissions, so the function never
# creates a log group.

_HANDLER = r'''
import json, os, boto3
_sqs = boto3.client("sqs")
def handler(event, context):
    _sqs.send_message(QueueUrl=os.environ["CAPTURE_URL"], MessageBody=json.dumps(event))
    return {"ok": True}
'''


def _zip_handler() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("index.py")
        info.external_attr = 0o644 << 16
        zf.writestr(info, _HANDLER)
    return buf.getvalue()


def _create_queue(ctx, prefix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _capturing_function(ctx, topic_arn: str) -> tuple[str, str]:
    """(function ARN, capture queue URL) for a function SNS may invoke from ``topic_arn``."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    capture_url, capture_arn = _create_queue(ctx, "sim2real-behav-sns-cap-")
    role = ctx.unique_name("sim2real-behav-sns-fn-")
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    iam.put_role_policy(RoleName=role, PolicyName="capture", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": capture_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName="capture"))

    fn = ctx.unique_name("sim2real-behav-sns-fn-")
    deadline = time.monotonic() + 90
    while True:
        try:
            fn_arn = lam.create_function(
                FunctionName=fn, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": _zip_handler()}, Timeout=10,
                Environment={"Variables": {"CAPTURE_URL": capture_url}},
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            break
        except ClientError as exc:
            # A just-created execution role is not yet assumable by Lambda; nothing to poll.
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    lam.add_permission(FunctionName=fn, StatementId="sns", Action="lambda:InvokeFunction",
                       Principal="sns.amazonaws.com", SourceArn=topic_arn)
    return fn_arn, capture_url


def _captured(ctx, capture_url: str, want, timeout_s: float) -> list[dict]:
    """Drain the capture queue until ``want(events)`` holds or the deadline passes."""
    sqs = ctx.client("sqs")
    out: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = sqs.receive_message(QueueUrl=capture_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for m in resp.get("Messages", []):
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=capture_url, ReceiptHandle=m["ReceiptHandle"])
        if want(out) or time.monotonic() >= deadline:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
