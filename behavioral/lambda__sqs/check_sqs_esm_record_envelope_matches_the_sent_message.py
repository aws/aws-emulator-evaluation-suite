"""sqs-esm-record-envelope-matches-the-sent-message."""
from __future__ import annotations

import hashlib
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-record-envelope-matches-the-sent-message"
GROUP = "event-propagation"
SERVICES = ["lambda", "sqs"]

_HANDLER = """\
import json, os
import boto3

def handler(event, context):
    sqs = boto3.client("sqs")
    for record in event["Records"]:
        sqs.send_message(QueueUrl=os.environ["SINK_URL"], MessageBody=json.dumps(record))
    return {"n": len(event["Records"])}
"""

_REQUIRED_KEYS = {"messageId", "receiptHandle", "body", "attributes", "messageAttributes",
                  "md5OfBody", "eventSource", "eventSourceARN", "awsRegion"}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SQS mapping's record is the sent message: same messageId, body and md5OfBody, eventSource
    aws:sqs, the queue ARN and region, ApproximateReceiveCount "1", SentTimestamp <= first-receive
    time, and the message is deleted after success.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html
    """
    sqs = ctx.client("sqs")
    src = _queue(ctx, VisibilityTimeout="60")
    sink = _queue(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage",
                                       "sqs:GetQueueAttributes"], "Resource": src["arn"]},
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink["arn"]},
    ])
    fn = _function(ctx, role["arn"], _HANDLER, env={"SINK_URL": sink["url"]})
    _mapping(ctx, EventSourceArn=src["arn"], FunctionName=fn["name"], BatchSize=1)

    body = "café ✓ " + ctx.unique_name("marker-") + ' {"nested": [1, 2]}'
    sent = sqs.send_message(QueueUrl=src["url"], MessageBody=body)
    want_md5 = hashlib.md5(body.encode("utf-8"), usedforsecurity=False).hexdigest()
    assert sent["MD5OfMessageBody"] == want_md5, (
        f"SendMessage MD5OfMessageBody {sent['MD5OfMessageBody']!r} != md5(body) {want_md5!r}")

    got = _collect_until(ctx, sink["url"], lambda s: any(r.get("messageId") == sent["MessageId"]
                                                         for r in s),
                         timeout_s=120, what="the function forwards the record of the sent message")
    rec = next(r for r in got if r.get("messageId") == sent["MessageId"])
    missing = _REQUIRED_KEYS - set(rec)
    assert not missing, f"the record lacks {sorted(missing)!r}; keys were {sorted(rec)!r}"
    assert rec["body"] == body, f"record body {rec['body']!r} != sent body {body!r}"
    assert rec["md5OfBody"] == want_md5, f"md5OfBody {rec['md5OfBody']!r} != {want_md5!r}"
    assert rec["eventSource"] == "aws:sqs", f"eventSource {rec['eventSource']!r}"
    assert rec["eventSourceARN"] == src["arn"], (
        f"eventSourceARN {rec['eventSourceARN']!r} != the source queue's QueueArn {src['arn']!r}")
    assert rec["awsRegion"] == ctx.region, f"awsRegion {rec['awsRegion']!r} != {ctx.region!r}"
    assert isinstance(rec["receiptHandle"], str) and rec["receiptHandle"], (
        f"receiptHandle {rec['receiptHandle']!r} is not a non-empty string")
    assert rec["messageAttributes"] == {}, (
        f"a message sent with no attributes carried messageAttributes {rec['messageAttributes']!r}")

    attrs = rec["attributes"]
    for k in ("ApproximateReceiveCount", "SentTimestamp", "SenderId",
              "ApproximateFirstReceiveTimestamp"):
        assert isinstance(attrs.get(k), str) and attrs[k], f"attribute {k} is {attrs.get(k)!r}"
    assert attrs["ApproximateReceiveCount"] == "1", (
        f"first delivery has ApproximateReceiveCount {attrs['ApproximateReceiveCount']!r}")
    assert attrs["SentTimestamp"].isdigit() and attrs["ApproximateFirstReceiveTimestamp"].isdigit(), (
        f"timestamps are not epoch-millisecond digit strings: {attrs!r}")
    assert int(attrs["SentTimestamp"]) <= int(attrs["ApproximateFirstReceiveTimestamp"]), (
        f"first receive precedes send: {attrs!r}")

    depth = _poll(lambda: _depth(ctx, src["url"]), lambda d: d == ("0", "0"), timeout_s=90,
                  interval_s=3, what="the processed message is deleted from the source queue")
    assert depth == ("0", "0"), f"source queue depth (visible, in flight) is {depth!r}"


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


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN, never a literal."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"unparseable caller ARN {arn!r}"
    return parts[1]


def _execution_role(ctx, statements) -> dict:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so the function
    never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, env=None, timeout=30) -> dict:
    """A python3.12 function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "python3.12", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}
    if env:
        kwargs["Environment"] = {"Variables": env}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _mapping(ctx, **kwargs) -> dict:
    """CreateEventSourceMapping through the role-propagation window, then poll it to Enabled."""
    lam = ctx.client("lambda")

    def create():
        try:
            return lam.create_event_source_mapping(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    esm = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateEventSourceMapping accepts the fresh execution role")
    uuid = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    want = "Enabled" if kwargs.get("Enabled", True) else "Disabled"
    _poll(lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == want,
          timeout_s=120, interval_s=2, what=f"mapping {uuid} reaches {want}")
    return esm


_NO_QUEUE = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")


def _queue(ctx, name_suffix="", **attrs) -> dict:
    """A queue of ours, tagged, with its delete registered. Returns {url, arn, name}."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-") + name_suffix
    url = sqs.create_queue(QueueName=name, Attributes=attrs,
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url), *_NO_QUEUE))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn, "name": name}


def _drain(ctx, url, *, window_s) -> list:
    """Every message the queue yields over ``window_s`` seconds, each deleted once read."""
    sqs = ctx.client("sqs")
    seen = []
    deadline = time.monotonic() + window_s
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return seen
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=max(1, min(5, int(left))))
        for m in resp.get("Messages", []):
            seen.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


def _collect_until(ctx, url, done, *, timeout_s, what) -> list:
    """Drain ``url`` until ``done(everything so far)``; raises naming ``what`` on timeout."""
    seen = []
    deadline = time.monotonic() + timeout_s
    while not done(seen):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; saw {seen!r}")
        seen.extend(_drain(ctx, url, window_s=5))
    return seen


def _depth(ctx, url) -> tuple:
    a = ctx.client("sqs").get_queue_attributes(QueueUrl=url, AttributeNames=[
        "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"]
    return a["ApproximateNumberOfMessages"], a["ApproximateNumberOfMessagesNotVisible"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
