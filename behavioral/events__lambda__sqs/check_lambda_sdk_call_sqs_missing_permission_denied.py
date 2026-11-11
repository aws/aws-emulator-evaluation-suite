"""lambda-sdk-call-sqs-missing-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-call-sqs-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role lacks sqs:SendMessage gets AccessDenied and nothing lands on the
    queue; with the permission granted the identical call delivers the message."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    queue = _create_queue(ctx)

    handler_code = (
        "import boto3, json, os\n"
        "from botocore.exceptions import ClientError\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    try:\n"
        "        resp = sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=event['payload'])\n"
        "        return {'ok': True, 'messageId': resp['MessageId']}\n"
        "    except ClientError as e:\n"
        "        return {'ok': False, 'errorCode': e.response['Error']['Code']}\n"
    )

    # --- Negative path: role with no SQS permissions at all.
    bare_role_arn = _create_role(ctx, "lambda.amazonaws.com")
    bare_fn = _create_function(ctx, bare_role_arn, code=handler_code, env={"QUEUE_URL": queue["url"]})

    resp = lam.invoke(
        FunctionName=bare_fn["name"],
        InvocationType="RequestResponse",
        Payload=json.dumps({"payload": "should-be-denied"}).encode(),
    )
    payload = json.loads(resp["Payload"].read())
    assert payload["ok"] is False, f"expected the SDK call to fail without permission, got: {payload}"
    assert payload["errorCode"] == "AccessDenied", (
        f"expected AccessDenied for a role with no sqs:SendMessage grant, got: {payload['errorCode']!r}"
    )

    # Effect is absent: nothing was enqueued.
    drained = _drain(sqs, queue["url"], wait=5)
    assert drained == [], f"expected no message to have landed in the queue, got: {drained!r}"

    # --- Positive control: identical code, role WITH the permission.
    good_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "send-to-sqs": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue["arn"]}
                ],
            }
        },
    )
    good_fn = _create_function(ctx, good_role_arn, code=handler_code, env={"QUEUE_URL": queue["url"]})

    resp2 = lam.invoke(
        FunctionName=good_fn["name"],
        InvocationType="RequestResponse",
        Payload=json.dumps({"payload": "should-succeed"}).encode(),
    )
    payload2 = json.loads(resp2["Payload"].read())
    assert payload2["ok"] is True, f"expected the identical call to succeed once permission is granted, got: {payload2}"

    messages = _poll_until(
        lambda: _drain(sqs, queue["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert messages[0]["Body"] == "should-succeed", (
        f"expected the permitted send to land in the queue, got: {messages[0]!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _drain(sqs, url, max_msgs=10, wait=2):
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=max_msgs, WaitTimeSeconds=wait)
    return resp.get("Messages", [])


def _create_role(ctx, trust_service, inline_policies=None, managed_arns=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _cleanup():
        for pname in list((inline_policies or {}).keys()):
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for marn in (managed_arns or []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=marn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for marn in (managed_arns or []):
        iam.attach_role_policy(RoleName=name, PolicyArn=marn)
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _create_function(ctx, role_arn, code, handler="handler.handler", env=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", code)
    zip_bytes = buf.getvalue()
    deadline = time.monotonic() + 40.0
    resp = None
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2,
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_queue(ctx, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    suffix = ".fifo" if fifo else ""
    name = ctx.unique_name("sim2real-q-") + suffix
    attrs = dict(extra_attrs or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs, tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
