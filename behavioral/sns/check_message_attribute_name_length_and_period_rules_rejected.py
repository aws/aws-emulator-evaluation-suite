"""message-attribute-name-length-and-period-rules-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-attribute-name-length-and-period-rules-rejected"
GROUP = "message-attribute-limits"
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
    """Publish refuses a 257-char attribute name and leading, trailing or doubled periods with
    ParameterValueInvalid, delivering none; a 256-char name and "a.b.c" are delivered intact.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-attrname-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-attrname-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
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

    def attr(name: str) -> dict:
        return {name: {"DataType": "String", "StringValue": "v"}}

    long_ok = "n" * 256
    refusals = {
        "n" * 257: "Length of message attribute name must be less than 256 bytes.",
        ".lead": "Invalid message attribute name starting with character '.' was found.",
        "trail.": "Invalid message attribute name ending with character '.' was found.",
        "a..b": "Message attribute name can not have successive '.' character.",
    }
    observed = {name: _error(lambda name=name: sns.publish(
        TopicArn=topic, Message=f"refused-{name[:12]}", MessageAttributes=attr(name)))
        for name in refusals}
    wrong = {name[:20]: got for name, got in observed.items()
             if got != ("ParameterValueInvalid", refusals[name])}
    assert not wrong, f"attribute-name refusals differ from the rules: {wrong!r}"

    ok_body = ctx.unique_name("sim2real-attrname-ok-")
    mid = sns.publish(TopicArn=topic, Message=ok_body, MessageAttributes={
        long_ok: {"DataType": "String", "StringValue": "long"},
        "a.b.c": {"DataType": "String", "StringValue": "dotted"}})["MessageId"]

    envs = []
    deadline, tail = time.monotonic() + 90, None
    while time.monotonic() < deadline and (tail is None or time.monotonic() < tail):
        if tail is None and any(e.get("MessageId") == mid for e in envs):
            # Keep receiving briefly after the accepted message so a late refused one shows up.
            tail = time.monotonic() + 6
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []):
            envs.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert [e.get("MessageId") for e in envs] == [mid], (
        f"the queue must hold only the accepted message; it received {len(envs)} message(s), "
        f"bodies {[str(e.get('Message'))[:20] for e in envs]!r}")
    assert envs[0].get("MessageAttributes") == {
        long_ok: {"Type": "String", "Value": "long"}, "a.b.c": {"Type": "String", "Value": "dotted"}}, (
        f"the delivered attributes are {sorted((k[:20], len(k)) for k in envs[0].get('MessageAttributes', {}))!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
