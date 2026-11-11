"""function-sdk-sends-an-sqs-message-the-caller-receives."""
from __future__ import annotations

import hashlib
import io
import json
import textwrap
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-sdk-sends-an-sqs-message-the-caller-receives"
GROUP = "compute"
SERVICES = ["lambda"]

_BASIC_EXEC_POLICY = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_HANDLER = """\
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    sqs = boto3.client("sqs")
    try:
        url = sqs.get_queue_url(QueueName=event["queue"])["QueueUrl"]
        sent = sqs.send_message(
            QueueUrl=url, MessageBody=event["body"],
            MessageAttributes={"sender": {"DataType": "String", "StringValue": context.function_name}},
        )
    except ClientError as e:
        return {"error": e.response["Error"]["Code"]}
    return {"message_id": sent["MessageId"], "md5": sent["MD5OfMessageBody"]}
"""


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _execution_role(ctx, iam, queue_arn) -> str:
    """A Lambda execution role with basic logging and GetQueueUrl/SendMessage on the check's queue."""
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role(RoleName=name)))
    basic_exec = _BASIC_EXEC_POLICY.format(partition=_partition(ctx))
    iam.attach_role_policy(RoleName=name, PolicyArn=basic_exec)
    ctx.on_cleanup(lambda: _ignore_no_such_entity(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=basic_exec)))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["sqs:GetQueueUrl", "sqs:SendMessage"],
                       "Resource": queue_arn}],
    }
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-send", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: _ignore_no_such_entity(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-send")))
    return arn


def _delete_queue_if_exists(sqs, url) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            raise


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Function code using boto3 with no endpoint resolves the check's queue by name and sends to
    it: the caller receives exactly that message, with the message id and body MD5 the function was
    given, the body it sent and a sender attribute naming the function."""
    lam = ctx.client("lambda", config=Config(read_timeout=40, retries={"max_attempts": 0}))
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    queue = ctx.unique_name("sim2real-behav-fnsdk-")
    url = sqs.create_queue(QueueName=queue, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_if_exists(sqs, url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_arn = _execution_role(ctx, iam, queue_arn)
    fn = ctx.unique_name("sim2real-behav-fnsdk-")
    _create_function(
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _zip(_HANDLER)},
        MemorySize=256,
        Timeout=60,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx.client("logs"), f"/aws/lambda/{fn}"))
    ctx.on_cleanup(lambda: _delete_function_if_exists(lam, fn))
    _wait_active(lam, fn)

    body = json.dumps({"order": ctx.unique_name("o-"), "lines": [1, 2, 3], "note": "naïve café"})
    # The execution role's inline policy is eventually consistent on real AWS.
    out = _poll(lambda: _invoke(lam, fn, {"queue": queue, "body": body}),
                lambda r: r.get("error") != "AccessDenied",
                timeout_s=40, interval_s=5, what="the function's SQS calls are authorized")
    assert "error" not in out, (
        f"the function's own SQS call failed with {out['error']!r}: the SDK inside the function did "
        f"not reach this target's SQS"
    )
    want_md5 = hashlib.md5(body.encode("utf-8")).hexdigest()
    assert out.get("md5") == want_md5, f"the function's SendMessage MD5 {out.get('md5')!r}, expected {want_md5!r}"

    # A standard queue is at-least-once: copies of one message share its MessageId, so the received
    # messages are graded as the distinct set by MessageId.
    deadline = time.monotonic() + 40
    by_id: dict = {}
    last: list = []
    while out["message_id"] not in by_id:
        assert time.monotonic() < deadline, (
            f"the message {out['message_id']!r} the function sent was not received within 40s: "
            f"the last ReceiveMessage returned {last!r}")
        last = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   MessageAttributeNames=["All"]).get("Messages", [])
        for m in last:
            by_id.setdefault(m["MessageId"], m)
    assert set(by_id) == {out["message_id"]}, (
        f"the queue holds {len(by_id)} distinct messages, expected only the one the function sent")
    msg = by_id[out["message_id"]]
    assert msg["Body"] == body, f"received body {msg['Body']!r}, expected {body!r}"
    assert msg["MD5OfBody"] == want_md5, f"received MD5OfBody {msg['MD5OfBody']!r}, expected {want_md5!r}"
    sender = msg.get("MessageAttributes", {}).get("sender", {})
    assert sender == {"StringValue": fn, "DataType": "String"}, f"received sender attribute {sender!r}, expected {fn!r}"


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    deadline = time.monotonic() + 40
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "cannot be assumed" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _wait_active(lam, fn, timeout_s=40) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last.get("State") == "Failed":
            raise AssertionError(f"function {fn} entered Failed: {last.get('StateReason')!r}")
        if last.get("State", "Active") == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {fn} did not reach Active within {timeout_s}s: {last!r}")


def _invoke(lam, fn, event) -> dict:
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                      Payload=json.dumps(event).encode())
    raw = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(
            f"the function raised ({resp['FunctionError']}): {raw.decode(errors='replace')[:600]}"
        )
    out = json.loads(raw) if raw else None
    assert isinstance(out, dict), f"the function returned {raw[:300]!r}, expected a JSON object"
    return out


def _poll(probe, done, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if done(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")


def _ignore_no_such_entity(call) -> None:
    try:
        call()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_function_if_exists(lam, fn) -> None:
    try:
        lam.delete_function(FunctionName=fn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_log_group_if_exists(logs, name) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
