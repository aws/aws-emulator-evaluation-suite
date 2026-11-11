"""sqs-lambda-event-source-mapping-basic."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-lambda-event-source-mapping-basic"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda event source mapping on an SQS queue actually polls the queue and invokes the
    function with the real message body; on success the source message is consumed
    (removed from the queue) rather than staying visible forever."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    src_queue = _create_queue(ctx)
    out_queue = _create_queue(ctx)

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
            "import boto3, json, os\n"
            "def handler(event, context):\n"
            "    sqs = boto3.client('sqs')\n"
            "    for record in event['Records']:\n"
            "        sqs.send_message(QueueUrl=os.environ['OUT_URL'], MessageBody=record['body'])\n"
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

    sqs.send_message(QueueUrl=src_queue["url"], MessageBody="hello-from-sqs")

    delivered = _poll_until(
        lambda: _drain(sqs, out_queue["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert delivered[0]["Body"] == "hello-from-sqs", (
        f"expected the ESM-invoked function to relay body 'hello-from-sqs' to the "
        f"output queue, got {delivered[0]['Body']!r}"
    )

    # The source message was consumed on success -- it does not remain in the source queue.
    remaining = _poll_until(
        lambda: sqs.get_queue_attributes(
            QueueUrl=src_queue["url"],
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"],
        lambda a: int(a["ApproximateNumberOfMessages"]) == 0
        and int(a["ApproximateNumberOfMessagesNotVisible"]) == 0,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert remaining["ApproximateNumberOfMessages"] == "0", (
        f"expected the source queue to be fully drained after successful processing, "
        f"got ApproximateNumberOfMessages={remaining['ApproximateNumberOfMessages']!r}"
    )


_MANAGED_TAGS = {"sim2real:managed": "true"}


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
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
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
                Tags=dict(_MANAGED_TAGS),
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
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags=dict(_MANAGED_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
