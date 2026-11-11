"""function-sdk-send-to-unpermitted-queue-denied-as-function-error."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-sdk-send-to-unpermitted-queue-denied-as-function-error"
GROUP = "permission-chain"
SERVICES = ["lambda", "sqs"]

_HANDLER = """\
import boto3

def handler(event, context):
    r = boto3.client("sqs").send_message(QueueUrl=event["url"], MessageBody=event["body"])
    return {"messageId": r["MessageId"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Function SDK calls act as the execution role: SendMessage to the granted queue succeeds and is
    receivable, while SendMessage to an ungranted queue fails the invoke as Unhandled with SQS's
    exact AccessDenied message for the assumed-role session, and nothing lands there.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/python-exceptions.html
    """
    sqs = ctx.client("sqs")
    allowed = _queue(ctx)
    denied = _queue(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": allowed["arn"]},
    ])
    fn = _function(ctx, role["arn"], _HANDLER)
    part = _partition(ctx)

    marker = ctx.unique_name("ok-")
    err, out = _poll(lambda: _invoke(ctx, fn["name"], {"url": allowed["url"], "body": marker}),
                     lambda r: r[0] is None or "AccessDenied" not in json.dumps(r[1]),
                     timeout_s=90, interval_s=5, what="the role's sqs:SendMessage grant is effective")
    assert err is None, f"the permitted SendMessage failed the invocation: {err!r} {out!r}"
    msgs = sqs.receive_message(QueueUrl=allowed["url"], WaitTimeSeconds=10,
                               MaxNumberOfMessages=1).get("Messages", [])
    assert [m["Body"] for m in msgs] == [marker], f"the permitted queue holds {msgs!r}"
    assert msgs[0]["MessageId"] == out["messageId"], (
        f"received MessageId differs from the one the function was given: {out!r}")

    err, out = _invoke(ctx, fn["name"], {"url": denied["url"], "body": "must-not-arrive"})
    assert err == "Unhandled", f"the unpermitted SendMessage gave FunctionError {err!r}: {out!r}"
    principal = f"arn:{part}:sts::{ctx.account}:assumed-role/{role['name']}/{fn['name']}"
    want = (f"An error occurred (AccessDenied) when calling the SendMessage operation: User: "
            f"{principal} is not authorized to perform: sqs:sendmessage on resource: "
            f"{denied['arn']} because no identity-based policy allows the sqs:sendmessage action")
    assert out.get("errorMessage") == want, (
        f"errorMessage {out.get('errorMessage')!r}, expected {want!r}")
    stray = sqs.receive_message(QueueUrl=denied["url"], WaitTimeSeconds=10).get("Messages", [])
    assert stray == [], f"the denied queue received {stray!r}"


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
