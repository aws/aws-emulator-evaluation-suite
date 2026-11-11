"""sqs-fifo-lambda-message-group-order-preserved."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-fifo-lambda-message-group-order-preserved"
GROUP = "state"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Messages sent in order to one message group of a FIFO queue are forwarded by a Lambda event
    source mapping to a FIFO output queue in the same order, even across several batches."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    src_queue = _create_queue(ctx, fifo=True)
    out_queue = _create_queue(ctx, fifo=True)

    role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "esm-perms": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                        "Resource": src_queue["arn"],
                    },
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": out_queue["arn"]},
                ],
            }
        },
    )
    fn = _create_function(
        ctx,
        role_arn,
        code=(
            "import boto3, os\n"
            "def handler(event, context):\n"
            "    sqs = boto3.client('sqs')\n"
            "    for record in event['Records']:\n"
            "        sqs.send_message(\n"
            "            QueueUrl=os.environ['OUT_URL'],\n"
            "            MessageBody=record['body'],\n"
            "            MessageGroupId='g1',\n"
            "        )\n"
            "    return {'ok': True}\n"
        ),
        env={"OUT_URL": out_queue["url"]},
    )

    mapping = lam.create_event_source_mapping(
        EventSourceArn=src_queue["arn"], FunctionName=fn["name"], BatchSize=10
    )
    uuid = mapping["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid)["State"],
        lambda s: s == "Enabled",
        timeout_s=60.0,
        interval_s=2.0,
    )

    expected = [f"seq-{i}" for i in range(5)]
    for body in expected:
        sqs.send_message(QueueUrl=src_queue["url"], MessageBody=body, MessageGroupId="g1")

    received: list[dict] = []
    _poll_until(
        lambda: _drain_all(sqs, out_queue["url"], received),
        lambda msgs: len(msgs) >= len(expected),
        timeout_s=60.0,
        interval_s=2.0,
    )
    bodies = [m["Body"] for m in received[: len(expected)]]
    assert bodies == expected, f"message-group order not preserved: expected {expected}, got {bodies}"


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


def _drain_all(sqs, url, collected, max_rounds=5):
    # A FIFO queue withholds the rest of a message group from ReceiveMessage while an
    # earlier receive from that group is outstanding, so a received-but-undeleted message
    # would lock out its own group's remaining messages until the visibility timeout lapses.
    # Delete on receipt and accumulate across calls so no poll iteration loses what it saw.
    for _ in range(max_rounds):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        msgs = resp.get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        collected.extend(msgs)
    return collected


def _create_role(ctx, trust_service, inline_policies=None, managed_arns=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]

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
    url = sqs.create_queue(QueueName=name, Attributes=attrs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
