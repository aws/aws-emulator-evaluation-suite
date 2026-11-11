"""lambda-subscription-the-function-refuses-to-sns-dead-letters-into-the-subscription-dlq."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-subscription-the-function-refuses-to-sns-dead-letters-into-the-subscription-dlq"
GROUP = "lambda-delivery"
SERVICES = ["sns"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function that grants SNS no lambda:InvokeFunction is never invoked and the notification
    envelope is dead-lettered once; after AddPermission for the topic, the next notification
    invokes the function and is not dead-lettered.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-lperm-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    dlq_url, dlq_arn = _dead_letter_queue(ctx, topic)
    fn, fn_arn, capture = _capturing_function(ctx, topic, fail=False, grant_sns=False)

    sub = sns.subscribe(TopicArn=topic, Protocol="lambda", Endpoint=fn_arn, ReturnSubscriptionArn=True,
                        Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn})})["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    refused = ctx.unique_name("sim2real-lperm-refused-")
    mid = sns.publish(TopicArn=topic, Message=refused, Subject="refused")["MessageId"]
    dead = _drain_until(sqs, dlq_url, lambda d: any(e.get("MessageId") == mid for e in d), 240)
    letter = [e for e in dead if e.get("MessageId") == mid]
    assert len(letter) == 1, (
        f"the notification the function's policy refused must be dead-lettered once; found "
        f"{len(letter)} among {len(dead)} dead letter(s)")
    assert (letter[0].get("Type"), letter[0].get("TopicArn"), letter[0].get("Message"),
            letter[0].get("Subject")) == ("Notification", topic, refused, "refused"), (
        f"the dead letter must be the notification's JSON envelope; got Type "
        f"{letter[0].get('Type')!r}, Subject {letter[0].get('Subject')!r}, "
        f"Message matches={letter[0].get('Message') == refused}")
    assert _captured(ctx, capture, lambda evs: False, 6) == [], (
        "the function was invoked although its resource policy grants SNS nothing")

    # Positive control: grant the topic, and the same subscription delivers.
    lam.add_permission(FunctionName=fn, StatementId="sns", Action="lambda:InvokeFunction",
                       Principal="sns.amazonaws.com", SourceArn=topic)
    deadline = time.monotonic() + 180
    while True:
        ok = sns.publish(TopicArn=topic, Message=ctx.unique_name("sim2real-lperm-ok-"))["MessageId"]
        got = _captured(ctx, capture, lambda evs: _count(evs, ok) >= 1, 30)
        if _count(got, ok) >= 1:
            break
        # The new resource-policy statement propagates; nothing exposes when it is effective.
        assert time.monotonic() < deadline, "after AddPermission the function was never invoked by SNS"
    late = _drain_until(sqs, dlq_url, lambda d: False, 6)
    assert all(e.get("MessageId") != ok for e in late), "a notification the function received was also dead-lettered"


def _count(events: list[dict], message_id: str) -> int:
    return sum(1 for e in events for r in e.get("Records", []) if r["Sns"]["MessageId"] == message_id)


def _drain_until(sqs, url: str, done, timeout_s: float) -> list[dict]:
    out: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while True:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []):
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if done(out) or time.monotonic() >= deadline:
            return out


# The subscribed function copies the event it was invoked with into a capture queue, then raises
# when FAIL is "1". Its role can only send to that queue and has no CloudWatch Logs permissions,
# so the function never creates a log group.

_HANDLER = r'''
import json, os, boto3
_sqs = boto3.client("sqs")
def handler(event, context):
    _sqs.send_message(QueueUrl=os.environ["CAPTURE_URL"], MessageBody=json.dumps(event))
    if os.environ.get("FAIL") == "1":
        raise RuntimeError("sim2real deliberate failure")
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


def _dead_letter_queue(ctx, topic_arn: str) -> tuple[str, str]:
    url, arn = _create_queue(ctx, "sim2real-behav-sns-dlq-")
    ctx.client("sqs").set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})
    return url, arn


def _capturing_function(ctx, topic_arn: str, *, fail: bool, grant_sns: bool) -> tuple[str, str, str]:
    """(function name, function ARN, capture queue URL)."""
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
                Environment={"Variables": {"CAPTURE_URL": capture_url, "FAIL": "1" if fail else "0"}},
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
    if grant_sns:
        lam.add_permission(FunctionName=fn, StatementId="sns", Action="lambda:InvokeFunction",
                           Principal="sns.amazonaws.com", SourceArn=topic_arn)
    return fn, fn_arn, capture_url


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
