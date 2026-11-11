"""cross-region-lambda-subscription-invokes-the-function-in-its-own-region."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-region-lambda-subscription-invokes-the-function-in-its-own-region"
GROUP = "cross-region"
SERVICES = ["sns"]


def _other_region(region: str) -> str:
    """A second commercial region of the same account (region-pinned by design)."""
    return "us-east-1" if region != "us-east-1" else "us-west-2"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A topic invokes a Lambda function in another region via a topic-region subscription; the
    record names that subscription and topic, and the filter policy still blocks non-matches.
    """
    home = ctx.region
    away = _other_region(home)
    sns = ctx.client("sns")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-xrl-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    fn_arn, capture = _capturing_function(ctx, topic, away)
    assert fn_arn.split(":")[3] == away, f"the function ARN's region is {fn_arn.split(':')[3]!r}, expected {away!r}"

    sub = sns.subscribe(TopicArn=topic, Protocol="lambda", Endpoint=fn_arn, ReturnSubscriptionArn=True,
                        Attributes={"FilterPolicy": json.dumps({"route": ["cross"]})})["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    assert sub.startswith(topic + ":"), "the cross-region subscription must extend the topic's ARN"

    skipped = sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-xrl-skip-"),
                          MessageAttributes={"route": {"DataType": "String", "StringValue": "stay"}})["MessageId"]
    body = ctx.unique_name("sim2real-xrl-body-")
    mid = sns.publish(TopicArn=topic, Message=body,
                      MessageAttributes={"route": {"DataType": "String", "StringValue": "cross"}})["MessageId"]
    events = _captured(ctx, capture, away, lambda evs: mid in _ids(evs), 180)
    records = [r for e in events for r in e.get("Records", [])]
    hit = [r for r in records if r["Sns"]["MessageId"] == mid]
    assert len(hit) >= 1, f"the function in {away} was never invoked for the matching notification"
    rec = hit[0]
    assert (rec.get("EventSource"), rec.get("EventSubscriptionArn"), rec["Sns"].get("TopicArn"),
            rec["Sns"].get("Message")) == ("aws:sns", sub, topic, body), (
        f"the cross-region record must name the topic-region subscription and topic and carry the "
        f"body; EventSource {rec.get('EventSource')!r}, subscription matches="
        f"{rec.get('EventSubscriptionArn') == sub}, topic matches={rec['Sns'].get('TopicArn') == topic}")
    late = _captured(ctx, capture, away, lambda evs: False, 6)
    assert skipped not in _ids(events) | _ids(late), (
        "the function was invoked for a notification its subscription's filter policy rejects")


def _ids(events: list[dict]) -> set[str]:
    return {r.get("Sns", {}).get("MessageId") for e in events for r in e.get("Records", [])}


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


def _create_queue(ctx, prefix: str, region: str) -> tuple[str, str]:
    sqs = ctx.client("sqs", region=region)
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _capturing_function(ctx, topic_arn: str, region: str) -> tuple[str, str]:
    """(function ARN, capture queue URL), both in ``region``, for a function SNS may invoke
    from ``topic_arn``."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda", region=region)
    capture_url, capture_arn = _create_queue(ctx, "sim2real-behav-sns-cap-", region)
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


def _captured(ctx, capture_url: str, region: str, want, timeout_s: float) -> list[dict]:
    """Drain the capture queue until ``want(events)`` holds or the deadline passes."""
    sqs = ctx.client("sqs", region=region)
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
